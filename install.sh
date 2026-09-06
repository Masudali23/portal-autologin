#!/usr/bin/env bash
# Installer for portal-autologin.
#   ./install.sh              install + enable the 10-minute systemd timer
#   ./install.sh --cron       install + use a crontab entry instead of systemd
#   ./install.sh --no-timer   install only, schedule it yourself
#   ./install.sh --uninstall  remove the timer/cron entry and the program files
set -euo pipefail

APP=portal-autologin
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${XDG_DATA_HOME:-$HOME/.local/share}/$APP"
CONF="${XDG_CONFIG_HOME:-$HOME/.config}/$APP.conf"
UNITS="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
BIN="$HOME/.local/bin"
PY="$PREFIX/venv/bin/python"

c_ok()   { printf '\033[32m  ok\033[0m  %s\n' "$*"; }
c_info() { printf '\033[36m  ..\033[0m  %s\n' "$*"; }
c_warn() { printf '\033[33m  !!\033[0m  %s\n' "$*"; }
c_err()  { printf '\033[31m  xx\033[0m  %s\n' "$*" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

uninstall() {
  if have systemctl; then
    systemctl --user disable --now "$APP.timer" 2>/dev/null || true
    rm -f "$UNITS/$APP.timer" "$UNITS/$APP.service"
    systemctl --user daemon-reload 2>/dev/null || true
    c_ok "systemd timer removed"
  fi
  if have crontab && crontab -l 2>/dev/null | grep -q "$APP"; then
    crontab -l 2>/dev/null | grep -v "$APP" | crontab -
    c_ok "crontab entry removed"
  fi
  rm -rf "$PREFIX"; rm -f "$BIN/$APP"
  c_ok "program files removed ($PREFIX)"
  c_warn "kept your config: $CONF"
  c_warn "kept your logs:   ${XDG_STATE_HOME:-$HOME/.local/state}/$APP"
  exit 0
}

MODE=systemd
case "${1:-}" in
  --uninstall) uninstall ;;
  --cron)      MODE=cron ;;
  --no-timer)  MODE=none ;;
  "")          ;;
  *)           c_err "unknown option: $1"; exit 2 ;;
esac

echo "installing $APP"

# --- prerequisites ---------------------------------------------------------
have python3 || { c_err "python3 is required"; exit 1; }
c_ok "python3 $(python3 -V 2>&1 | cut -d' ' -f2)"

if ! python3 -c 'import venv' 2>/dev/null; then
  c_err "the python venv module is missing. Install it, e.g.:"
  echo "      Debian/Ubuntu : sudo apt install -y python3-venv"
  echo "      Fedora/RHEL   : sudo dnf install -y python3-virtualenv"
  exit 1
fi

BROWSER_FOUND=""
for b in google-chrome google-chrome-stable chromium chromium-browser brave-browser firefox firefox-esr; do
  if have "$b"; then BROWSER_FOUND="$b"; break; fi
done
if [ -n "$BROWSER_FOUND" ]; then
  c_ok "browser found: $BROWSER_FOUND"
else
  c_warn "no Chrome/Chromium/Firefox found on PATH. Install one, e.g.:"
  echo "      Debian/Ubuntu : sudo apt install -y chromium-browser   (or firefox-esr)"
  echo "      Fedora/RHEL   : sudo dnf install -y chromium           (or firefox)"
  echo "      Arch          : sudo pacman -S chromium                (or firefox)"
fi
case "$BROWSER_FOUND" in firefox*) ENGINE=firefox ;; *) ENGINE=chrome ;; esac

# --- files -----------------------------------------------------------------
mkdir -p "$PREFIX" "$BIN"
install -m 0755 "$SRC/$APP.py" "$PREFIX/$APP.py"
c_ok "installed $PREFIX/$APP.py"

c_info "creating virtualenv and installing selenium (needs internet once)"
python3 -m venv "$PREFIX/venv"
"$PY" -m pip install --quiet --upgrade pip >/dev/null
if ! "$PY" -m pip install --quiet "selenium>=4.15"; then
  c_err "could not install selenium. Connect to the internet (log in manually once) and re-run."
  exit 1
fi
c_ok "selenium $("$PY" -c 'import selenium;print(selenium.__version__)') installed"

# convenience wrapper on PATH
cat > "$BIN/$APP" <<WRAP
#!/usr/bin/env bash
exec "$PY" "$PREFIX/$APP.py" "\$@"
WRAP
chmod 0755 "$BIN/$APP"
c_ok "wrapper installed: $BIN/$APP"

# --- config ----------------------------------------------------------------
if [ -f "$CONF" ]; then
  c_ok "keeping existing config: $CONF"
else
  mkdir -p "$(dirname "$CONF")"
  install -m 0600 "$SRC/$APP.conf" "$CONF"
  sed -i "s/^engine = chrome$/engine = $ENGINE/" "$CONF" 2>/dev/null || true
  c_ok "config created: $CONF  (mode 600, engine=$ENGINE)"
fi
chmod 600 "$CONF"

# --- schedule --------------------------------------------------------------
case "$MODE" in
  systemd)
    if ! have systemctl || ! systemctl --user show-environment >/dev/null 2>&1; then
      c_warn "no usable systemd user session - falling back to cron"
      MODE=cron
    else
      mkdir -p "$UNITS"
      sed "s|%h|$HOME|g" "$SRC/$APP.service" > "$UNITS/$APP.service"
      cp "$SRC/$APP.timer" "$UNITS/$APP.timer"
      systemctl --user daemon-reload
      systemctl --user enable --now "$APP.timer"
      c_ok "systemd timer enabled (every 10 minutes)"
      loginctl enable-linger "$USER" >/dev/null 2>&1 \
        && c_ok "linger enabled - the timer also runs when you are not logged in" \
        || c_warn "could not enable linger; the timer runs only while you are logged in"
    fi
    ;;
esac

if [ "$MODE" = cron ]; then
  LINE="*/10 * * * * $PY $PREFIX/$APP.py --once >/dev/null 2>&1"
  ( crontab -l 2>/dev/null | grep -v "$APP" ; echo "$LINE" ) | crontab -
  c_ok "crontab entry added (every 10 minutes)"
fi

cat <<DONE

next steps
  1. put your credentials in the config:   \$EDITOR $CONF
  2. see what the portal login form looks like:
        $APP --inspect
     and copy the field names into the [selectors] section
  3. test it:
        $APP --check      # just report the state
        $APP --login -v   # force a login attempt, verbose
  4. watch it work:
        tail -f ${XDG_STATE_HOME:-$HOME/.local/state}/$APP/$APP.log
        systemctl --user list-timers $APP.timer

DONE
[ -d "$BIN" ] && case ":$PATH:" in *":$BIN:"*) ;; *)
  c_warn "$BIN is not on your PATH - add it to ~/.bashrc:  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac
