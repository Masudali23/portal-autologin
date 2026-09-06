# portal-autologin

Keeps a headless Linux box authenticated against a FortiGate captive portal, so
it stays reachable when the session expires overnight.

Pure **bash + curl**. No browser, no Selenium, no Python. Runs as a root systemd
unit, so it works with nobody logged in.

Every command below was run on a real machine and produced the output shown.

**Verified on:** Ubuntu 22.04.5 LTS, kernel 6.8, IIT (BHU) Varanasi FortiGate
portal on port 1000 — `192.168.249.1` on the departmental LAN, `192.168.252.1`
on wifi. The gateway is discovered at runtime, so moving between them needs no
config change.

---

## Read this first

**1. Four systems per account.** [CCIS](https://www.iitbhu.ac.in/cf/cis/network/faq)
caps an account at 4 concurrent systems, and clearing a "Concurrent Over-limit"
means visiting CCIS in person with your ID card. A script that blindly re-POSTs
credentials on a timer can mint hundreds of sessions overnight and put you there.

This tool logs in **only when connectivity is actually gone**, releases the slot
it holds via `/logout?` first, and refreshes the existing session through the
portal's own `/keepalive` URL when healthy — which costs no slot at all.

**2. No institute VPN.** CCIS states no VPN facility exists, and CAIT clause 10
prohibits "unauthorized server(s) and client(s) of any kind (e.g. vpn, proxy…)".
Ask your supervisor or CCIS before installing a tunnel. Steps 1–7 need none.

**3. Never put your password in this repo.** It goes in one root-only file on
the box, in step 4.

---

## Setup

### 1. Get the files onto the box

```bash
git clone https://github.com/Masudali23/portal-autologin.git && cd portal-autologin
```

```bash
chmod +x portal-login.sh portal-check.sh
```

### 2. Health check before installing anything

Read-only. Changes nothing, logs in to nothing, prints no passwords.

```bash
sudo ./portal-check.sh
```

Writes `portal-check-report.txt`. Check section 5 says `802-1x.password-flags 0`
— if it says `1`, NetworkManager asks a desktop session for your wifi password,
and at 3am there is no desktop session, so the box never even connects.

### 3. Install

```bash
sudo ./portal-login.sh install
```

Expected:

```
  ok  installed /usr/local/sbin/portal-login
  ok  created /etc/portal-login/portal-login.conf (mode 600)
  ok  systemd timer enabled (every 5 minutes, and 90s after every boot)
  ok  NetworkManager hook installed (/etc/NetworkManager/dispatcher.d/90-portal-login)
```

That gives you three independent layers: a check every 5 minutes, one 90 seconds
after every boot, and one the instant a network link comes up.

For an always-running process instead of the timer, use
`sudo ./portal-login.sh install --daemon`. Each mode disables the other. There is
no reliability difference; the timer is the default.

### 4. Credentials

```bash
sudo nano /etc/portal-login/portal-login.conf
```

Fill in these two lines — the same login you type into the browser popup:

```
PORTAL_USERNAME = your_campus_username
PORTAL_PASSWORD = your_campus_password
```

Save with **Ctrl-O**, Enter, exit with **Ctrl-X**. Then:

```bash
sudo chmod 600 /etc/portal-login/portal-login.conf && sudo ls -l /etc/portal-login/portal-login.conf
```

Expected: `-rw------- 1 root root`

No quotes needed. The file is *parsed*, never executed, so `#`, `=`, `$`, spaces
and backslashes in your password are all safe.

### 5. Confirm it reads the real portal

Must be run on the campus network.

```bash
sudo portal-login inspect
```

Expected:

```
discovered URL  : http://192.168.249.1:1000/fgtauth?11a40c7a34aa479b
form action     : /
NAME                       TYPE       VALUE
4Tredir                    hidden     http://connectivitycheck.gstatic.com/gen
magic                      hidden     11a40c7a34aa479b
username                   text
password                   password   ***

auto-detected   : USER_FIELD=username  PASS_FIELD=password
```

If `USER_FIELD`/`PASS_FIELD` are wrong, pin them in the config to bypass
auto-detection.

### 6. Force one login

```bash
sudo portal-login login -v
```

Expected to end with:

```
INFO  releasing the session we hold: http://192.168.249.1:1000/logout?<token>
INFO  fetching login page: http://192.168.249.1:1000/fgtauth?...
INFO  posting credentials to http://192.168.249.1:1000/
INFO  LOGIN OK - internet is reachable again
INFO  portal reports countDownTime=14400 (session is about 720 minutes)
```

`countDownTime × 3` seconds is your real session length. 14400 × 3 = 43200s = 12h.

### 7. Status

```bash
sudo portal-login status
```

Expected: `mode : systemd timer`, `passwd : <set>`, `fails : 0`, `now : ONLINE`,
and `last ok` within the last 5 minutes.

---

## Verify it is actually running

The timer spawns a short-lived process every 5 minutes. `ps` shows **nothing**
between runs and `systemctl is-active portal-login.service` says `inactive` —
both are correct. The thing that must be alive is the timer:

```bash
systemctl is-active portal-login.timer
```

Expected: `active`

Proof it is ticking:

```bash
journalctl -u portal-login -b -o short-iso | grep Starting
```

Expected — timestamps ~5 minutes apart:

```
2026-09-07T03:26:37+0530 devbot systemd[1]: Starting Captive portal auto-login...
2026-09-07T03:31:57+0530 devbot systemd[1]: Starting Captive portal auto-login...
2026-09-07T03:37:00+0530 devbot systemd[1]: Starting Captive portal auto-login...
```

Tight clusters a few seconds apart are the NetworkManager hook firing on a link
event, not the timer. Next run:

```bash
systemctl list-timers portal-login.timer --no-pager
```

`LEFT` and `PASSED` both under 5 minutes.

### After a reboot

`-b` limits the log to the current boot, so anything you see started itself.

```bash
uptime -s; journalctl -u portal-login -b -o short-iso | grep Starting
```

The first line should be ~90 seconds after the boot time. Wait 2 minutes after
booting before checking, or it will look broken when it is not.

### Are you genuinely online

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://connectivitycheck.gstatic.com/generate_204
```

`204` = real internet. Anything else = still behind the portal.

---

## The end-to-end test

Log yourself out at the gateway. No link changes, so the NetworkManager hook
cannot fire — only the timer can recover you.

```bash
curl -s "http://192.168.249.1:1000/logout?" >/dev/null; date
```

```bash
journalctl -u portal-login -f
```

Within 5 minutes, unattended:

```
INFO  state=NEED_LOGIN (connectivity probe was intercepted by a portal)
INFO  LOGIN OK - internet is reachable again
```

Ctrl-C to stop watching. **Do this while you are at the machine** — if it fails
you are offline until you log in by hand.

---

## Keep the box awake

```bash
sudo portal-login harden
```

Masks suspend/hibernate, tells logind to ignore idle and lid events, disables
wifi power-saving, sets NetworkManager to auto-reconnect with infinite retries.

```bash
sudo systemctl reload NetworkManager
```

`reload` re-reads the config without dropping connections. The logind settings
need no command — they apply at the next reboot.

> **Never run `systemctl restart systemd-logind`.** It tears down the running
> desktop session: black screen, machine looks hung, and the next shutdown can
> hang too. Nothing is gained by it. An earlier version of this README wrongly
> suggested it.

Confirm after a reboot:

```bash
systemctl is-enabled sleep.target suspend.target hibernate.target hybrid-sleep.target
```

All four should say `masked`.

---

## AnyDesk: `display_server_not_supported`

AnyDesk cannot capture a Wayland session, and Ubuntu 22.04 defaults to Wayland.

```bash
echo $XDG_SESSION_TYPE
```

If that says `wayland`:

```bash
sudo nano /etc/gdm3/custom.conf
```

Uncomment this line under `[daemon]` (remove the `#`):

```
WaylandEnable=false
```

```bash
sudo reboot
```

```bash
echo $XDG_SESSION_TYPE
```

Must now say `x11`. AnyDesk will then connect.

Two things this does **not** fix:

- Set an unattended-access password in AnyDesk, or someone has to be at the
  machine to click Accept.
- AnyDesk captures a *logged-in* session. After an unattended reboot the box sits
  at the login screen with nothing to capture.

For access that works headless, at the login screen, and after an unattended
reboot — with permission, see the policy note at the top:

```bash
sudo tailscale up --ssh --hostname gpu-box
```

```bash
ssh gpu-box
```

Confirm it works from your laptop before you rely on it.

---

## Updating

`git pull` alone does **not** update the installed copy. systemd runs
`/usr/local/sbin/portal-login`, so you must reinstall:

```bash
cd ~/portal-autologin && git pull && sudo ./portal-login.sh install && sudo portal-login -V
```

---

## Command reference

```bash
sudo portal-login check      # report state, never logs in
sudo portal-login once       # check, log in only if needed (what the timer runs)
sudo portal-login login      # force a login attempt now
sudo portal-login inspect    # dump the portal's real login form
sudo portal-login status     # config, state, mode, timer, recent log
sudo portal-login install    # add --daemon for an always-running service
sudo portal-login harden     # no suspend, no wifi powersave, autoreconnect
sudo portal-login uninstall  # remove it (keeps config and logs)
```

`-v` is **verbose**. `-V` is **version**. Exit codes: `0` ok · `1` login failed ·
`2` network down · `3` backing off · `4` misconfigured.

---

## Troubleshooting

**`portal-login` prints nothing at all** — you are on a version before 2.0.1,
where a lock bug (`exec 9>file 2>/dev/null`, which redirects stderr permanently
rather than for that command alone) silenced every log line whenever `flock` was
present. Reinstall as shown under Updating.

**Nothing happens at 3am but it works while you are logged in** — the 802.1X
secret is agent-owned. Check and fix:

```bash
nmcli -f 802-1x.identity,802-1x.password-flags,connection.permissions connection show "YOUR-PROFILE"
```

```bash
sudo nmcli connection modify "YOUR-PROFILE" 802-1x.password-flags 0 connection.permissions "" connection.autoconnect yes connection.autoconnect-retries 0
```

Test by rebooting and checking connectivity **before** logging in graphically.

**`NetworkManager-wait-online.service` failed** — usually collateral from
restarting NetworkManager by hand. Harmless; clear it:

```bash
sudo systemctl reset-failed NetworkManager-wait-online.service
```

**"could not find a password field"** — run `sudo portal-login inspect` and set
`USER_FIELD`/`PASS_FIELD` in the config. The raw page is saved to
`/var/lib/portal-login/last-page.html`.

**Login submitted but connectivity never returns** — the portal's reply is at
`/var/lib/portal-login/last-result.html`. The classic FortiGate failure is a
stale `magic` token: HTTP 200 and the login page again, with no error text. This
tool takes `magic` from a single fresh intercept per attempt, never follows
redirects while doing so, and retries once with a new token before giving up.

**Different gateway on wifi vs LAN** — normal. IIT BHU runs a FortiGate per zone.
`PORTAL_URL` in the config is only a last-resort fallback; the gateway is read
from the interception at runtime.

**Before enabling `REBOOT_AFTER_OFFLINE_MIN`** — it is off by default, and two
things make it harmful:

```bash
lsblk -o NAME,TYPE,FSTYPE | grep crypt
```

If the root is LUKS, the box reboots to a passphrase prompt and stays there. Also
check the BIOS "Restore on AC Power Loss" setting — it often defaults to *Power
Off*, so after a cut the machine never comes back at all and no script helps.

---

## One caveat

The portal speaks plain HTTP on port 1000, so your campus password crosses the
LAN unencrypted — with this tool, with your browser, with anything. That is the
portal's design. Port 1003 (HTTPS) does not help; the certificate will not
validate and you would need `-k` anyway. Use a password you do not reuse, and
note you cannot rotate it without an in-person CCIS visit.

## Licence

MIT
