#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
portal-autologin - keep a captive-portal / gateway login session alive.

Strategy
--------
1. CHEAP CHECK (stdlib only, ~1 second, no browser):
     * probe well-known connectivity endpoints (204 / success.txt)
     * probe the portal page itself
   A browser is NEVER launched unless a login is actually required.

2. LOGIN (only when needed): headless Chrome or Firefox via Selenium.
   Field detection is automatic, and every selector can be overridden
   in the config file when the heuristics don't match your portal.

3. VERIFY: after submitting, re-run the connectivity probe. The login is
   only reported as successful if the internet really came back.

Modes
-----
  --check     report state and exit (never logs in)
  --once      check, and log in if needed          <- use this from cron/systemd
  --daemon    loop forever using [schedule] interval
  --login     force a login attempt right now
  --inspect   open the portal in a browser and dump the login form

Credentials live in the config file (chmod 600) or in the environment
(PORTAL_USERNAME / PORTAL_PASSWORD). They are never passed on the command
line and never written to the log.
"""

from __future__ import annotations

import argparse
import configparser
import json
import logging
import os
import random
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlparse

APP = "portal-autologin"
VERSION = "1.2.0"

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

# (url, expected status, expected body substring)
INTERNET_PROBES = [
    ("http://connectivitycheck.gstatic.com/generate_204", 204, ""),
    ("http://detectportal.firefox.com/success.txt", 200, "success"),
    ("http://www.msftconnecttest.com/connecttest.txt", 200, "Microsoft Connect Test"),
]

LOGIN_WORDS = ("password", "username", "user name", "userid", "log in", "login",
               "sign in", "signin", "authenticate", "captive")

ONLINE, NEED_LOGIN, NETWORK_DOWN, UNKNOWN = "ONLINE", "NEED_LOGIN", "NETWORK_DOWN", "UNKNOWN"

log = logging.getLogger(APP)


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------

def config_candidates() -> list[Path]:
    here = Path(__file__).resolve().parent
    xdg = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    out = []
    env = os.environ.get("PORTAL_AUTOLOGIN_CONF")
    if env:
        out.append(Path(env).expanduser())
    out += [
        xdg / APP / "config.conf",
        xdg / f"{APP}.conf",
        Path.home() / f".{APP}.conf",
        Path("/etc") / APP / "config.conf",
        Path("/etc") / f"{APP}.conf",
        here / f"{APP}.conf",
    ]
    return out


def state_dir() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    d = base / APP
    d.mkdir(parents=True, exist_ok=True)
    return d


class Cfg:
    """Thin, forgiving wrapper over configparser."""

    def __init__(self, path: Path | None):
        self.path = path
        p = configparser.ConfigParser(interpolation=None)   # '%' in passwords is fine
        p.optionxform = str.lower
        if path and path.is_file():
            p.read(path, encoding="utf-8")
        self._p = p

        # [portal]
        self.url = self.s("portal", "url", "http://192.168.252.1:1000/")
        self.username = os.environ.get("PORTAL_USERNAME") or self.s("portal", "username")
        self.password = os.environ.get("PORTAL_PASSWORD") or self.s("portal", "password")
        self.extra_url = self.s("portal", "login_url")          # optional direct form URL
        self.unreachable_means_online = self.b("portal", "unreachable_means_logged_in", True)
        self.trust_portal_only = self.b("portal", "trust_portal_only", False)
        self.use_proxy = self.b("portal", "use_system_proxy", False)
        self.probe_timeout = self.f("portal", "probe_timeout", 5.0)

        # [selectors] - leave blank to auto-detect
        self.sel_user = self.s("selectors", "username")
        self.sel_pass = self.s("selectors", "password")
        self.sel_submit = self.s("selectors", "submit")
        self.sel_success = self.s("selectors", "success_text")
        self.confirm_words = [w.strip().lower() for w in
                              self.s("selectors", "confirm_words",
                                     "continue,yes,ok,proceed,login anyway,override").split(",")
                              if w.strip()]

        # [browser]
        self.browser = self.s("browser", "engine", "chrome").lower()
        self.headless = self.b("browser", "headless", True)
        self.binary = self.s("browser", "binary")
        self.driver = self.s("browser", "driver")
        self.no_sandbox = self.b("browser", "no_sandbox", False)
        self.page_timeout = self.f("browser", "page_timeout", 30.0)
        self.after_submit_wait = self.f("browser", "after_submit_wait", 4.0)
        self.verify_timeout = self.f("browser", "verify_timeout", 30.0)
        self.keep_debug = self.b("browser", "save_debug_on_failure", True)

        # [schedule]
        self.interval = self.f("schedule", "interval_seconds", 600.0)
        self.jitter = self.f("schedule", "jitter_seconds", 20.0)
        self.backoff_base = self.f("schedule", "backoff_base_seconds", 600.0)
        self.backoff_max = self.f("schedule", "backoff_max_seconds", 3600.0)
        self.max_fail_notify = self.i("schedule", "notify_after_failures", 3)

        # [logging]
        self.notify = self.b("logging", "desktop_notify", True)
        self.log_file = self.s("logging", "file", str(state_dir() / f"{APP}.log"))
        self.log_level = self.s("logging", "level", "info").upper()

    # -- typed getters ------------------------------------------------------
    def s(self, sec: str, key: str, default: str = "") -> str:
        try:
            v = self._p.get(sec, key)
        except Exception:
            return default
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]                       # allow quoting to preserve spaces
        return v

    def b(self, sec: str, key: str, default: bool) -> bool:
        v = self.s(sec, key, "").lower()
        if v in ("1", "yes", "true", "on"):
            return True
        if v in ("0", "no", "false", "off"):
            return False
        return default

    def f(self, sec: str, key: str, default: float) -> float:
        try:
            return float(self.s(sec, key, ""))
        except ValueError:
            return default

    def i(self, sec: str, key: str, default: int) -> int:
        return int(self.f(sec, key, float(default)))


# --------------------------------------------------------------------------
# logging
# --------------------------------------------------------------------------

def setup_logging(cfg: Cfg, verbose: bool) -> None:
    log.setLevel(logging.DEBUG if verbose else getattr(logging, cfg.log_level, logging.INFO))
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")

    try:
        Path(cfg.log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(cfg.log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        fh.setFormatter(fmt)
        log.addHandler(fh)
    except OSError as e:
        print(f"warning: cannot write log file {cfg.log_file}: {e}", file=sys.stderr)

    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    log.addHandler(sh)


def notify(cfg: Cfg, title: str, body: str, urgent: bool = False) -> None:
    if not cfg.notify:
        return
    exe = shutil.which("notify-send")
    if not exe:
        return
    try:
        subprocess.run([exe, "-a", APP, "-u", "critical" if urgent else "normal", title, body],
                       timeout=5, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


# --------------------------------------------------------------------------
# connectivity probes (stdlib only - no browser, no third-party modules)
# --------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None                      # surface the 3xx itself: that IS the portal


def _opener(cfg: Cfg, follow: bool):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE      # portals routinely use self-signed certs
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not cfg.use_proxy:
        handlers.append(urllib.request.ProxyHandler({}))
    if not follow:
        handlers.append(_NoRedirect())
    return urllib.request.build_opener(*handlers)


def http_get(cfg: Cfg, url: str, follow: bool = False, timeout: float | None = None):
    """Return (status, body_text, final_url) or raise."""
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Cache-Control": "no-cache, no-store",
        "Pragma": "no-cache",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    to = cfg.probe_timeout if timeout is None else timeout
    try:
        with _opener(cfg, follow).open(req, timeout=to) as r:
            body = r.read(65536).decode("utf-8", "replace")
            return r.status, body, r.geturl()
    except urllib.error.HTTPError as e:                    # 4xx/5xx still tell us a lot
        body = ""
        try:
            body = e.read(65536).decode("utf-8", "replace")
        except Exception:
            pass
        return e.code, body, url


def probe_internet(cfg: Cfg):
    """True = really online, False = intercepted by a portal, None = no answer at all.

    The first probe that actually answers decides: a clean 204/success body means
    we are through, anything else (redirect, portal HTML, error page) means we are
    being intercepted. None only when every probe times out or is refused.
    """
    for url, want_status, want_body in INTERNET_PROBES:
        try:
            status, body, _ = http_get(cfg, url, follow=False)
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
            log.debug("probe %s failed: %s", url, e)
            continue
        if status == want_status and (not want_body or want_body in body):
            log.debug("probe %s -> clean (%s)", url, status)
            return True
        log.debug("probe %s -> intercepted (status=%s, %d bytes)", url, status, len(body))
        return False
    return None


def probe_portal(cfg: Cfg) -> dict:
    """Is the portal page reachable, and does it look like a login form?"""
    info = {"reachable": False, "login_page": False, "status": None, "body": "", "error": ""}
    u = urlparse(cfg.url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)

    # TCP first: distinguishes "gateway gone" from "HTTP layer refused us"
    try:
        with socket.create_connection((host, port), timeout=min(cfg.probe_timeout, 4.0)):
            pass
    except OSError as e:
        info["error"] = f"tcp {host}:{port}: {e}"
        return info

    try:
        status, body, _ = http_get(cfg, cfg.url, follow=True)
    except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
        info["error"] = f"http: {e}"
        return info

    low = body.lower()
    info.update(reachable=True, status=status, body=body,
                login_page=any(w in low for w in LOGIN_WORDS))
    return info


def classify(cfg: Cfg) -> tuple[str, str]:
    """Return (state, human readable reason)."""
    net = probe_internet(cfg)
    if net is True and not cfg.trust_portal_only:
        return ONLINE, "connectivity probe returned a clean response"

    portal = probe_portal(cfg)

    if net is False:
        return NEED_LOGIN, "connectivity probe was intercepted (captive portal active)"

    # net is None (or we were told to trust the portal only)
    if portal["reachable"]:
        if portal["login_page"]:
            return NEED_LOGIN, f"portal answered {portal['status']} with a login form"
        return NEED_LOGIN, f"portal answered {portal['status']} (assuming session expired)"

    if cfg.unreachable_means_online:
        return ONLINE, f"portal is not answering ({portal['error']}) -> session still valid"
    return NETWORK_DOWN, f"no internet and no portal ({portal['error']})"


# --------------------------------------------------------------------------
# browser
# --------------------------------------------------------------------------

def build_driver(cfg: Cfg, headless: bool | None = None):
    from selenium import webdriver

    headless = cfg.headless if headless is None else headless
    tmp_profile = tempfile.mkdtemp(prefix=f"{APP}-profile-")

    if cfg.browser.startswith("f"):                       # firefox
        from selenium.webdriver.firefox.options import Options
        from selenium.webdriver.firefox.service import Service
        o = Options()
        if headless:
            o.add_argument("-headless")
        if cfg.binary:
            o.binary_location = cfg.binary
        o.accept_insecure_certs = True
        o.set_preference("network.captive-portal-service.enabled", False)  # no duelling logins
        o.set_preference("network.connectivity-service.enabled", False)
        o.set_preference("browser.safebrowsing.malware.enabled", False)
        o.set_preference("browser.safebrowsing.phishing.enabled", False)
        o.set_preference("datareporting.healthreport.uploadEnabled", False)
        o.set_preference("toolkit.telemetry.enabled", False)
        o.set_preference("signon.rememberSignons", False)
        if not cfg.use_proxy:
            o.set_preference("network.proxy.type", 0)
        svc = Service(executable_path=cfg.driver) if cfg.driver else Service()
        drv = webdriver.Firefox(options=o, service=svc)
    else:                                                 # chrome / chromium
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        o = Options()
        if headless:
            o.add_argument("--headless=new")
        if cfg.binary:
            o.binary_location = cfg.binary
        for a in ("--disable-gpu", "--disable-dev-shm-usage", "--window-size=1280,900",
                  "--ignore-certificate-errors", "--allow-insecure-localhost",
                  "--no-first-run", "--no-default-browser-check",
                  "--disable-background-networking", "--disable-sync",
                  "--disable-popup-blocking", "--disable-notifications",
                  "--password-store=basic", "--disable-features=Translate,OptimizationHints",
                  f"--user-data-dir={tmp_profile}"):
            o.add_argument(a)
        if cfg.no_sandbox:
            o.add_argument("--no-sandbox")
        if not cfg.use_proxy:
            o.add_argument("--no-proxy-server")
        o.set_capability("acceptInsecureCerts", True)
        svc = Service(executable_path=cfg.driver) if cfg.driver else Service()
        drv = webdriver.Chrome(options=o, service=svc)

    drv.set_page_load_timeout(cfg.page_timeout)
    drv._tmp_profile = tmp_profile                        # noqa: SLF001 - cleaned up by caller
    return drv


def close_driver(drv) -> None:
    if drv is None:
        return
    try:
        drv.quit()
    except Exception:
        pass
    shutil.rmtree(getattr(drv, "_tmp_profile", "") or "/nonexistent", ignore_errors=True)


# ---- element helpers ------------------------------------------------------

USER_SELECTORS = [
    "input[name*='user' i]", "input[id*='user' i]",
    "input[name*='login' i]", "input[id*='login' i]",
    "input[name*='uname' i]", "input[name*='uid' i]", "input[name*='account' i]",
    "input[type='email']", "input[name*='email' i]",
    "input[type='text']:not([disabled])",
]
PASS_SELECTORS = ["input[type='password']:not([disabled])",
                  "input[name*='pass' i]", "input[id*='pass' i]"]
SUBMIT_SELECTORS = [
    "input[type='submit']", "button[type='submit']",
    "button[id*='login' i]", "button[name*='login' i]", "button[class*='login' i]",
    "input[id*='login' i]", "input[name*='login' i]",
    "input[type='button'][value*='log' i]", "button",
]


def _visible(elements):
    for el in elements:
        try:
            if el.is_displayed() and el.is_enabled():
                return el
        except Exception:
            continue
    return None


def find_one(drv, selectors):
    from selenium.webdriver.common.by import By
    for sel in selectors:
        if not sel:
            continue
        try:
            el = _visible(drv.find_elements(By.CSS_SELECTOR, sel))
        except Exception:
            continue
        if el is not None:
            return el, sel
    return None, ""


def enter_login_frame(drv, deadline: float) -> bool:
    """Find the document (top or iframe) that actually holds a password field."""
    from selenium.webdriver.common.by import By
    while time.time() < deadline:
        try:
            drv.switch_to.default_content()
            if _visible(drv.find_elements(By.CSS_SELECTOR, "input[type='password']")):
                return True
            frames = drv.find_elements(By.CSS_SELECTOR, "iframe, frame")
            for i in range(len(frames)):
                drv.switch_to.default_content()
                fr = drv.find_elements(By.CSS_SELECTOR, "iframe, frame")
                if i >= len(fr):
                    break
                try:
                    drv.switch_to.frame(fr[i])
                except Exception:
                    continue
                if _visible(drv.find_elements(By.CSS_SELECTOR, "input[type='password']")):
                    log.debug("login form found inside frame #%d", i)
                    return True
            drv.switch_to.default_content()
        except Exception as e:
            log.debug("frame scan: %s", e)
        time.sleep(0.5)
    return False


def click_text(drv, words) -> bool:
    from selenium.webdriver.common.by import By
    lc = "translate({},'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')"
    parts = []
    for w in words:
        w = w.lower().replace("'", "")
        parts.append(f"//button[contains({lc.format('normalize-space(.)')},'{w}')]")
        parts.append(f"//a[contains({lc.format('normalize-space(.)')},'{w}')]")
        parts.append(f"//input[(@type='submit' or @type='button') "
                     f"and contains({lc.format('@value')},'{w}')]")
    try:
        el = _visible(drv.find_elements(By.XPATH, " | ".join(parts)))
    except Exception:
        return False
    if el is None:
        return False
    return safe_click(drv, el)


def safe_click(drv, el) -> bool:
    try:
        drv.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
    except Exception:
        pass
    try:
        el.click()
        return True
    except Exception:
        try:
            drv.execute_script("arguments[0].click();", el)   # beats overlays/animations
            return True
        except Exception as e:
            log.debug("click failed: %s", e)
            return False


def type_into(drv, el, text: str) -> None:
    try:
        el.clear()
    except Exception:
        pass
    try:
        el.send_keys(text)
    except Exception:
        drv.execute_script(
            "arguments[0].value=arguments[1];"
            "arguments[0].dispatchEvent(new Event('input',{bubbles:true}));"
            "arguments[0].dispatchEvent(new Event('change',{bubbles:true}));", el, text)


def save_debug(cfg: Cfg, drv, tag: str) -> None:
    if not cfg.keep_debug:
        return
    d = state_dir() / "debug"
    d.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    try:
        drv.switch_to.default_content()
    except Exception:
        pass
    try:
        drv.save_screenshot(str(d / f"{stamp}-{tag}.png"))
    except Exception:
        pass
    try:
        html = drv.page_source
        if cfg.password:
            html = html.replace(cfg.password, "********")
        (d / f"{stamp}-{tag}.html").write_text(html, encoding="utf-8")
    except Exception:
        pass
    old = sorted(d.glob("*"))[:-10]                        # keep the last 10 artifacts
    for f in old:
        try:
            f.unlink()
        except OSError:
            pass
    log.info("debug artifacts written to %s", d)


# --------------------------------------------------------------------------
# the actual login
# --------------------------------------------------------------------------

def verify_online(cfg: Cfg, seconds: float) -> bool:
    deadline = time.time() + seconds
    while True:
        if probe_internet(cfg) is True:
            return True
        if time.time() >= deadline:
            return False
        time.sleep(3)


def do_login(cfg: Cfg) -> bool:
    if not cfg.username or not cfg.password:
        log.error("username/password not set - edit %s (or export PORTAL_USERNAME / "
                  "PORTAL_PASSWORD)", cfg.path or "the config file")
        return False

    from selenium.webdriver.common.keys import Keys

    drv = None
    try:
        log.info("launching headless %s", "firefox" if cfg.browser.startswith("f") else "chrome")
        drv = build_driver(cfg)
        target = cfg.extra_url or cfg.url
        log.info("opening %s", target)
        try:
            drv.get(target)
        except Exception as e:
            log.warning("page load reported %s - continuing anyway", e)

        deadline = time.time() + cfg.page_timeout
        if not enter_login_frame(drv, deadline):
            # Maybe we are already through, or the portal shows an interstitial.
            if click_text(drv, cfg.confirm_words):
                log.info("clicked an interstitial button, re-checking for the form")
                time.sleep(2)
            if not enter_login_frame(drv, time.time() + 8):
                if verify_online(cfg, 5):
                    log.info("no login form, but we are online - nothing to do")
                    return True
                log.error("no password field found on the portal page")
                save_debug(cfg, drv, "noform")
                return False

        pw_el, pw_sel = find_one(drv, ([cfg.sel_pass] if cfg.sel_pass else []) + PASS_SELECTORS)
        user_el, user_sel = find_one(drv, ([cfg.sel_user] if cfg.sel_user else []) + USER_SELECTORS)
        if pw_el is None:
            log.error("password field vanished before it could be filled")
            save_debug(cfg, drv, "nopass")
            return False

        log.info("filling credentials (user field: %s, password field: %s)",
                 user_sel or "<none>", pw_sel)
        if user_el is not None:
            type_into(drv, user_el, cfg.username)
        type_into(drv, pw_el, cfg.password)

        submit_el, submit_sel = find_one(
            drv, ([cfg.sel_submit] if cfg.sel_submit else []) + SUBMIT_SELECTORS)
        if submit_el is not None and safe_click(drv, submit_el):
            log.info("submitted via %s", submit_sel)
        elif click_text(drv, ("login", "log in", "sign in", "connect", "submit")):
            log.info("submitted via button text")
        else:
            log.info("no submit button matched - pressing ENTER in the password field")
            try:
                pw_el.send_keys(Keys.RETURN)
            except Exception:
                drv.execute_script(
                    "var f=arguments[0].form; if(f){ if(f.requestSubmit) f.requestSubmit();"
                    " else f.submit(); }", pw_el)

        time.sleep(cfg.after_submit_wait)

        # Some portals ask "you are already logged in elsewhere - continue?"
        try:
            drv.switch_to.default_content()
        except Exception:
            pass
        if not verify_online(cfg, 3):
            if click_text(drv, cfg.confirm_words):
                log.info("confirmed a secondary prompt")
                time.sleep(cfg.after_submit_wait)

        if cfg.sel_success:
            try:
                if cfg.sel_success.lower() in drv.page_source.lower():
                    log.info("success marker %r present on the page", cfg.sel_success)
            except Exception:
                pass

        if verify_online(cfg, cfg.verify_timeout):
            log.info("LOGIN OK - internet is reachable again")
            return True

        log.error("login submitted but the connectivity probe still fails")
        save_debug(cfg, drv, "failed")
        return False

    except Exception as e:
        log.error("login attempt crashed: %s: %s", type(e).__name__, e)
        if drv is not None:
            save_debug(cfg, drv, "crash")
        return False
    finally:
        close_driver(drv)


def do_inspect(cfg: Cfg) -> int:
    """Dump the portal's form so selectors can be pinned down."""
    drv = None
    try:
        drv = build_driver(cfg)
        drv.get(cfg.extra_url or cfg.url)
        time.sleep(3)
        enter_login_frame(drv, time.time() + 10)
        js = """
        const out = [];
        document.querySelectorAll('input,button,select,textarea,form').forEach(e => {
          out.push({tag:e.tagName, type:e.type||'', name:e.name||'', id:e.id||'',
                    cls:e.className||'', ph:e.placeholder||'', value:(e.type==='password'?'***':(e.value||'')).slice(0,40),
                    action:e.action||'', method:e.method||'',
                    text:(e.innerText||'').trim().slice(0,40),
                    shown:!!(e.offsetWidth||e.offsetHeight)});
        });
        return JSON.stringify({title:document.title, url:location.href, els:out});
        """
        data = json.loads(drv.execute_script(js))
        print(f"\ntitle : {data['title']}\nurl   : {data['url']}\n")
        print(f"{'TAG':<9}{'TYPE':<10}{'NAME':<22}{'ID':<22}{'PLACEHOLDER/TEXT':<26}VIS")
        print("-" * 100)
        for e in data["els"]:
            print(f"{e['tag']:<9}{e['type'][:9]:<10}{e['name'][:21]:<22}{e['id'][:21]:<22}"
                  f"{(e['ph'] or e['text'])[:25]:<26}{'y' if e['shown'] else 'n'}")
            if e["tag"] == "FORM":
                print(f"           -> action={e['action']} method={e['method']}")
        print("\nPut the winning selectors in the [selectors] section of your config, e.g.")
        print("   username = input[name='username']")
        print("   password = input[name='password']")
        print("   submit   = input[type='submit']\n")
        save_debug(cfg, drv, "inspect")
        return 0
    except Exception as e:
        log.error("inspect failed: %s: %s", type(e).__name__, e)
        return 1
    finally:
        close_driver(drv)


# --------------------------------------------------------------------------
# state, locking, run loop
# --------------------------------------------------------------------------

def load_state() -> dict:
    f = state_dir() / "state.json"
    try:
        return json.loads(f.read_text())
    except Exception:
        return {"fails": 0, "next_attempt": 0, "last_state": "", "last_ok": 0}


def save_state(st: dict) -> None:
    try:
        (state_dir() / "state.json").write_text(json.dumps(st, indent=2))
    except OSError:
        pass


def acquire_lock():
    """Single instance only - the timer must never stack browsers on top of each other."""
    import fcntl
    f = open(state_dir() / "lock", "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        return None
    f.write(str(os.getpid()))
    f.flush()
    return f


def run_once(cfg: Cfg, force: bool = False) -> int:
    st = load_state()
    now = time.time()

    if force:
        state, reason = NEED_LOGIN, "forced by --login"
    else:
        state, reason = classify(cfg)
    log.info("state=%s (%s)", state, reason)

    if state == ONLINE:
        if st.get("fails"):
            log.info("clearing %d recorded failure(s)", st["fails"])
        save_state({"fails": 0, "next_attempt": 0, "last_state": state, "last_ok": now})
        return 0

    if state == NETWORK_DOWN:
        save_state({**st, "last_state": state})
        log.warning("network appears to be down - not attempting a login")
        return 2

    if not force and now < st.get("next_attempt", 0):
        wait = int(st["next_attempt"] - now)
        log.warning("backing off after %d failure(s); next attempt in %ds",
                    st.get("fails", 0), wait)
        return 3

    ok = do_login(cfg)
    if ok:
        save_state({"fails": 0, "next_attempt": 0, "last_state": ONLINE, "last_ok": time.time()})
        notify(cfg, "Portal login", "Signed back in to the network.")
        return 0

    fails = st.get("fails", 0) + 1
    delay = min(cfg.backoff_base * (2 ** (fails - 1)), cfg.backoff_max)
    save_state({"fails": fails, "next_attempt": time.time() + delay,
                "last_state": NEED_LOGIN, "last_ok": st.get("last_ok", 0)})
    log.error("login failed (%d in a row); next attempt in %ds", fails, int(delay))
    if fails == cfg.max_fail_notify:
        notify(cfg, "Portal login failing",
               f"{fails} failed attempts. Check {cfg.log_file}", urgent=True)
    return 1


def run_daemon(cfg: Cfg) -> int:
    log.info("daemon mode: checking every %ds (+/- %ds jitter)",
             int(cfg.interval), int(cfg.jitter))
    while True:
        try:
            run_once(cfg)
        except KeyboardInterrupt:
            log.info("interrupted - exiting")
            return 0
        except Exception as e:
            log.error("unexpected error in loop: %s: %s", type(e).__name__, e)
        nap = max(30.0, cfg.interval + random.uniform(-cfg.jitter, cfg.jitter))
        log.debug("sleeping %.0fs", nap)
        try:
            time.sleep(nap)
        except KeyboardInterrupt:
            return 0


# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        prog=APP, description="Keep a captive-portal login session alive.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Credentials come from the config file or PORTAL_USERNAME/PORTAL_PASSWORD.")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true", help="report state only, never log in")
    g.add_argument("--once", action="store_true", help="check and log in if needed (default)")
    g.add_argument("--login", action="store_true", help="force a login attempt now")
    g.add_argument("--daemon", action="store_true", help="loop forever using [schedule] interval")
    g.add_argument("--inspect", action="store_true", help="dump the portal's login form")
    ap.add_argument("-c", "--config", help="path to the config file")
    ap.add_argument("-u", "--url", help="override the portal URL")
    ap.add_argument("-b", "--browser", choices=["chrome", "chromium", "firefox"],
                    help="override the browser engine")
    ap.add_argument("--headful", action="store_true", help="show the browser window (debugging)")
    ap.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    ap.add_argument("-V", "--version", action="version", version=f"{APP} {VERSION}")
    a = ap.parse_args()

    path = Path(a.config).expanduser() if a.config else next(
        (p for p in config_candidates() if p.is_file()), None)
    cfg = Cfg(path)
    if a.url:
        cfg.url = a.url
    if a.browser:
        cfg.browser = a.browser
    if a.headful:
        cfg.headless = False

    setup_logging(cfg, a.verbose)
    log.debug("%s %s, config=%s, portal=%s, browser=%s",
              APP, VERSION, path or "<defaults>", cfg.url, cfg.browser)

    if path and path.is_file():
        mode = path.stat().st_mode & 0o777
        if mode & 0o077 and (cfg.password or "") and not os.environ.get("PORTAL_PASSWORD"):
            log.warning("%s is mode %o and holds a password - run: chmod 600 %s",
                        path, mode, path)
    elif not (cfg.username and cfg.password):
        log.warning("no config file found; looked in: %s",
                    ", ".join(str(p) for p in config_candidates()))

    if a.check:
        state, reason = classify(cfg)
        print(f"{state}: {reason}")
        return 0 if state == ONLINE else 1

    if a.inspect:
        return do_inspect(cfg)

    lock = acquire_lock()
    if lock is None:
        log.info("another instance is already running - exiting")
        return 0
    try:
        if a.daemon:
            return run_daemon(cfg)
        return run_once(cfg, force=a.login)
    finally:
        try:
            lock.close()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
