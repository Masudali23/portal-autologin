#!/usr/bin/env bash
#
# portal-login.sh - unattended captive-portal re-authentication for Linux and macOS.
#
#   Keeps a machine logged in to a gateway captive portal (IIT BHU / FortiGate
#   style, http://<gateway>:1000/) so that long-running work and remote access
#   survive the periodic forced re-login, including at 3am with nobody around.
#
#   Pure bash + curl. No browser, no Python, no Selenium, no chromedriver.
#
# QUICK START
#   sudo ./portal-login.sh install      # copy to /usr/local/sbin + systemd units
#   sudo nano /etc/portal-login/portal-login.conf     # put credentials here
#   sudo portal-login inspect           # show the portal's real form fields
#   sudo portal-login login             # force one login, verbose
#   sudo portal-login status            # timer state + recent log
#
# COMMANDS
#   check      report ONLINE / NEED_LOGIN / NETWORK_DOWN and exit (never logs in)
#   once       check, and log in only if needed          <- what the timer runs
#   login      force a login attempt right now
#   daemon     loop forever (alternative to the systemd timer)
#   inspect    dump the portal login form so you can pin field names
#   install    install binary + config + systemd timer + NetworkManager hook
#                --daemon  install an always-running service instead of the timer
#                --timer   (default) run a check every 5 minutes
#   uninstall  remove all of the above (keeps your config and logs)
#   harden     opt-in system tweaks: no suspend, no wifi powersave, autoreconnect
#   status     show timer/service state and the last log lines
#
# EXIT CODES
#   0 online (or login succeeded)   1 login failed   2 network down
#   3 backing off after failures    4 configuration error
#
set -uo pipefail

VERSION=2.4.0
APP=portal-login
SELF=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")

# Linux and macOS share this script. macOS differs in the service manager
# (launchd, not systemd), the network tooling (route/ifconfig, not ip/nmcli),
# and a few paths; everything is branched on IS_MAC.
OS_NAME=$(uname -s 2>/dev/null || echo Linux)
IS_MAC=no; [ "$OS_NAME" = Darwin ] && IS_MAC=yes

# --------------------------------------------------------------------------
# defaults - every one of these can be overridden in the config file
# --------------------------------------------------------------------------
PORTAL_URL="http://192.168.252.1:1000/"
PORTAL_USERNAME=""
PORTAL_PASSWORD=""

LOGIN_URL=""              # set only if the form is NOT at PORTAL_URL
USER_FIELD=""             # blank = auto-detect from the HTML
PASS_FIELD=""             # blank = auto-detect (input[type=password])
EXTRA_FIELDS=""           # literal extra POST pairs, e.g. "realm=students&lang=en"
INTERFACE="auto"          # auto = the physical NIC; a name pins it; "any" = don't pin
FORCE_IPV4=yes            # see detect_phys_iface() for why this is not optional here
LOGOUT_BEFORE_LOGIN=yes   # free the old session slot before taking a new one
KEEPALIVE_ENABLED=yes     # hold the session open instead of re-logging in
HEARTBEAT_URL=""          # pinged on every confirmed-online check (dead-man's switch)

PROBE_URLS="http://connectivitycheck.gstatic.com/generate_204|204|
http://detectportal.firefox.com/success.txt|200|success
http://www.msftconnecttest.com/connecttest.txt|200|Microsoft Connect Test
http://captive.apple.com/hotspot-detect.html|200|Success"

CONNECT_TIMEOUT=5
MAX_TIME=15
VERIFY_ATTEMPTS=6         # after submitting, re-probe this many times
VERIFY_DELAY=3            # ...this many seconds apart

CHECK_INTERVAL=300        # daemon mode only; the timer has its own interval
JITTER=30
BACKOFF_BASE=300          # after a failed login, wait this long, then double
BACKOFF_MAX=3600
ALERT_AFTER_FAILURES=3
ALERT_COMMAND=""          # e.g. curl -s -d "portal login failing" ntfy.sh/mytopic

KEEPALIVE_URL=""          # optional URL to poke while online (FortiGate: .../keepalive)
LOG_LEVEL=info            # debug | info | warn | error
LOG_FILE=""               # blank = stdout only (journald captures it)
TRUST_PORTAL_ONLY=no      # yes = ignore internet probes, decide from the portal page
REBOOT_AFTER_OFFLINE_MIN=0   # 0 = never. Last-resort watchdog.

UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# --------------------------------------------------------------------------
# paths - system-wide when root, per-user otherwise
# --------------------------------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then
  CONF_FILE="${PORTAL_LOGIN_CONF:-/etc/$APP/$APP.conf}"
  if [ "$IS_MAC" = yes ]; then
    STATE_DIR="${PORTAL_LOGIN_STATE:-/var/db/$APP}"      # /var/lib does not exist on macOS
  else
    STATE_DIR="${PORTAL_LOGIN_STATE:-/var/lib/$APP}"
  fi
else
  CONF_FILE="${PORTAL_LOGIN_CONF:-${XDG_CONFIG_HOME:-$HOME/.config}/$APP/$APP.conf}"
  STATE_DIR="${PORTAL_LOGIN_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/$APP}"
fi
LOCK_FILE=""
LOCK_DIR_HELD=""
COOKIE_JAR=""
STATE_FILE=""
TMP=""

# --------------------------------------------------------------------------
# logging  (never prints the password - everything goes through redact())
# --------------------------------------------------------------------------
# bash 3.2 has no ${x,,} / ${x^^}, and this script has to run on whatever bash
# the machine happens to ship. tr is everywhere.
lc() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
uc() { printf '%s' "$1" | tr 'a-z' 'A-Z'; }

_lvl_num() {
  case "$(lc "$1")" in
    debug) echo 10 ;; info) echo 20 ;; warn|warning) echo 30 ;;
    error) echo 40 ;; *) echo 20 ;;
  esac
}

redact() {
  local s=$1
  [ -n "$PORTAL_PASSWORD" ] && s=${s//"$PORTAL_PASSWORD"/********}
  printf '%s' "$s"
}

log() {
  local level=$1; shift
  [ "$(_lvl_num "$level")" -lt "$(_lvl_num "$LOG_LEVEL")" ] && return 0
  local line
  line="$(date '+%Y-%m-%d %H:%M:%S') $(printf '%-5s' "$(uc "$level")") $(redact "$*")"
  printf '%s\n' "$line" >&2
  [ -n "$LOG_FILE" ] && printf '%s\n' "$line" >>"$LOG_FILE" 2>/dev/null
  return 0
}
debug() { log debug "$@"; }
info()  { log info  "$@"; }
warn()  { log warn  "$@"; }
err()   { log error "$@"; }

die() { err "$*"; exit 4; }

have() { command -v "$1" >/dev/null 2>&1; }

box_name() { printf '%s' "${HOSTNAME:-$(uname -n 2>/dev/null || echo unknown)}"; }

cleanup() {
  [ -n "$TMP" ] && rm -rf "$TMP"
  [ -n "$LOCK_DIR_HELD" ] && rm -rf "$LOCK_DIR_HELD"
  return 0
}

# Only one instance at a time: the systemd timer and the NetworkManager hook can
# easily fire together when a link comes up right on a tick boundary.
# flock is the right tool; mkdir is the fallback because it is atomic everywhere.
acquire_lock() {
  if have flock; then
    # NOTE: `exec 9>f 2>/dev/null` would ALSO redirect stderr permanently and
    # silence every subsequent log line. Keep the stderr redirect inside the
    # group; the fd 9 assignment still persists because {} is not a subshell.
    { exec 9>"$LOCK_FILE"; } 2>/dev/null || return 0
    flock -n 9 2>/dev/null || return 1
    return 0
  fi
  local d="$LOCK_FILE.d" pid
  if mkdir "$d" 2>/dev/null; then
    printf '%s' "$$" > "$d/pid" 2>/dev/null
    LOCK_DIR_HELD=$d
    return 0
  fi
  pid=$(cat "$d/pid" 2>/dev/null)
  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
    warn "clearing a stale lock (pid ${pid:-unknown} is gone)"
    rm -rf "$d"
    mkdir "$d" 2>/dev/null || return 1
    printf '%s' "$$" > "$d/pid" 2>/dev/null
    LOCK_DIR_HELD=$d
    return 0
  fi
  return 1
}

# `timeout` is coreutils and normally present, but never assume it exists.
run_limited() {
  local secs=$1; shift
  if have timeout; then timeout "$secs" "$@"; else "$@"; fi
}

# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------
# The config is KEY=VALUE, but it is PARSED, not sourced, so a stray character
# in a password can never execute anything. Values may be quoted; everything
# after the first '=' is taken literally to end of line otherwise.
load_config() {
  [ -f "$CONF_FILE" ] || { debug "no config file at $CONF_FILE"; return 0; }

  local perms
  perms=$(stat -c '%a' "$CONF_FILE" 2>/dev/null || stat -f '%Lp' "$CONF_FILE" 2>/dev/null || echo 600)
  case "$perms" in
    *[1-7][0-7]|*[0-7][1-7]) warn "$CONF_FILE is mode $perms and holds a password. Run: chmod 600 $CONF_FILE" ;;
  esac

  local key val _probes=""
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    case "$line" in ''|'#'*|';'*|'['*) continue ;; esac
    [[ $line == *=* ]] || continue
    key=${line%%=*}
    val=${line#*=}
    key=$(printf '%s' "$key" | tr -d ' \t')
    key=$(uc "$key")
    # strip one leading space after '=' and matching surrounding quotes
    val=${val# }
    if [ ${#val} -ge 2 ]; then
      case "$val" in
        \"*\") val=${val:1:${#val}-2} ;;
        \'*\') val=${val:1:${#val}-2} ;;
      esac
    fi
    case "$key" in
      PORTAL_URL|PORTAL_USERNAME|PORTAL_PASSWORD|LOGIN_URL|USER_FIELD|PASS_FIELD|\
      EXTRA_FIELDS|INTERFACE|FORCE_IPV4|LOGOUT_BEFORE_LOGIN|KEEPALIVE_ENABLED|\
      HEARTBEAT_URL|PROBE_URLS|CONNECT_TIMEOUT|MAX_TIME|VERIFY_ATTEMPTS|\
      VERIFY_DELAY|CHECK_INTERVAL|JITTER|BACKOFF_BASE|BACKOFF_MAX|ALERT_AFTER_FAILURES|\
      ALERT_COMMAND|KEEPALIVE_URL|LOG_LEVEL|LOG_FILE|TRUST_PORTAL_ONLY|\
      REBOOT_AFTER_OFFLINE_MIN|UA)
        printf -v "$key" '%s' "$val" ;;
      PROBE)
        # repeatable: PROBE = <url>|<expected status>|<expected body substring>
        _probes="$_probes$val
" ;;
      *) debug "ignoring unknown config key: $key" ;;
    esac
  done < "$CONF_FILE"
  [ -n "$_probes" ] && PROBE_URLS=$_probes

  # environment always wins (systemd LoadCredential / EnvironmentFile)
  [ -n "${PORTAL_USERNAME_OVERRIDE:-}" ] && PORTAL_USERNAME=$PORTAL_USERNAME_OVERRIDE
  [ -n "${PORTAL_PASSWORD_OVERRIDE:-}" ] && PORTAL_PASSWORD=$PORTAL_PASSWORD_OVERRIDE
  # systemd credentials: LoadCredential=portal-password:/etc/portal-login/password
  if [ -n "${CREDENTIALS_DIRECTORY:-}" ]; then
    [ -r "$CREDENTIALS_DIRECTORY/portal-username" ] && \
      PORTAL_USERNAME=$(<"$CREDENTIALS_DIRECTORY/portal-username")
    [ -r "$CREDENTIALS_DIRECTORY/portal-password" ] && \
      PORTAL_PASSWORD=$(<"$CREDENTIALS_DIRECTORY/portal-password")
  fi
  PORTAL_USERNAME=${PORTAL_USERNAME%$'\n'}
  PORTAL_PASSWORD=${PORTAL_PASSWORD%$'\n'}
  return 0
}

setup_runtime() {
  mkdir -p "$STATE_DIR" 2>/dev/null || STATE_DIR=$(mktemp -d)
  chmod 700 "$STATE_DIR" 2>/dev/null || true
  LOCK_FILE="$STATE_DIR/lock"
  COOKIE_JAR="$STATE_DIR/cookies.txt"
  STATE_FILE="$STATE_DIR/state"
  touch "$COOKIE_JAR" 2>/dev/null && chmod 600 "$COOKIE_JAR" 2>/dev/null || true
  TMP=$(mktemp -d "${TMPDIR:-/tmp}/$APP.XXXXXX") || die "cannot create temp dir"
  chmod 700 "$TMP"
  trap cleanup EXIT INT TERM
  if [ -n "$LOG_FILE" ]; then
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    touch "$LOG_FILE" 2>/dev/null || { warn "cannot write $LOG_FILE"; LOG_FILE=""; }
  fi
}

# --------------------------------------------------------------------------
# curl
# --------------------------------------------------------------------------
# --noproxy '*'  a system proxy would make every probe lie
# --insecure     captive portals almost always use a self-signed cert
# --max-time     an unattended script must never hang forever
# Which NIC do we actually mean?
#
# This matters far more than it looks. Two ways the connectivity probe can lie:
#
#   IPv6 - the FortiGate intercepts IPv4/HTTP. If the campus hands out routable
#          IPv6, glibc prefers it, the probe gets a real 204, and we conclude
#          "online" while every IPv4 connection is still captive.
#   Tunnels - once Tailscale/WireGuard is up the box has another interface. If a
#          route ever sends the probe through the tunnel, the probe keeps
#          returning 204 long after the campus session died, and this script
#          would sit there all night believing everything is fine.
#
# So: force IPv4, and pin every request to the physical NIC that holds the
# default route, explicitly skipping tunnel and bridge interfaces.
PHYS_IFACE=""
TUNNEL_DEFAULT=no         # set when the default route belongs to a VPN/tunnel
detect_phys_iface() {
  [ -n "$PHYS_IFACE" ] && { printf '%s' "$PHYS_IFACE"; return; }
  local i
  if [ "$IS_MAC" = yes ]; then
    i=$(route -n get default 2>/dev/null | awk '/interface:/ { print $2; exit }')
    case "$i" in
      utun*|gif*|stf*|bridge*|awdl*|llw*|ap*|anpi*|lo*|'')
        [ -n "$i" ] && { TUNNEL_DEFAULT=yes; warn "the default route is via '$i' (a tunnel/virtual interface) - looking for a physical NIC"; }
        local c; i=""
        for c in $(ifconfig -l 2>/dev/null); do
          case "$c" in en*) ipconfig getifaddr "$c" >/dev/null 2>&1 && { i=$c; break; } ;; esac
        done ;;
    esac
    PHYS_IFACE=$i
    [ -n "$i" ] && debug "pinning requests to interface $i"
    printf '%s' "$i"; return
  fi
  have ip || return 0
  i=$(ip -4 route show default 2>/dev/null |
      awk '{ for (n = 1; n < NF; n++) if ($n == "dev") { print $(n+1); exit } }')
  case "$i" in
    tailscale*|docker*|virbr*|wg*|tun*|tap*|br-*|zt*|veth*|lo)
      TUNNEL_DEFAULT=yes
      warn "the default route is via '$i' (a tunnel/bridge) - looking for a physical NIC"
      i=$(ip -4 route show 2>/dev/null |
          awk '{ for (n = 1; n < NF; n++) if ($n == "dev") print $(n+1) }' |
          grep -vE '^(tailscale|docker|virbr|wg|tun|tap|br-|zt|veth|lo)' | head -1) ;;
  esac
  PHYS_IFACE=$i
  [ -n "$i" ] && debug "pinning requests to interface $i"
  printf '%s' "$i"
}

CURL_ARGS=()
curl_opts() {
  CURL_ARGS=( --silent --show-error
              --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME"
              --insecure --noproxy '*'
              --user-agent "$UA"
              --header 'Cache-Control: no-cache, no-store'
              --header 'Pragma: no-cache' )
  [ "$(lc "$FORCE_IPV4")" = "yes" ] && CURL_ARGS+=( --ipv4 )
  [ "${NO_PIN:-0}" = 1 ] && return 0          # a deliberately unpinned probe
  local _i
  case "$(lc "$INTERFACE")" in
    ''|any|none) : ;;
    auto)   _i=$(detect_phys_iface) ;;
    *)      _i=$INTERFACE ;;
  esac
  if [ -n "$_i" ]; then
    # macOS curl needs the explicit "if!" prefix to be sure it binds an interface
    # name rather than trying it as a hostname; Linux accepts the bare name.
    [ "$IS_MAC" = yes ] && CURL_ARGS+=( --interface "if!$_i" ) || CURL_ARGS+=( --interface "$_i" )
  fi
  return 0
}

# http_get <url> <bodyfile> [--follow]
# echoes "<http_code> <effective_url> <redirect_url>"; returns 0 if curl ran,
# 2 if the request could not be completed at all (timeout / refused / no route).
http_get() {
  local url=$1 bodyfile=$2 follow=${3:-}
  curl_opts; local opts=( "${CURL_ARGS[@]}" )
  [ "$follow" = "--follow" ] && opts+=( --location --max-redirs 10 )
  local out rc
  out=$(curl "${opts[@]}" -o "$bodyfile" \
             -w '%{http_code} %{url_effective} %{redirect_url}' "$url" 2>"$TMP/curl.err")
  rc=$?
  if [ $rc -ne 0 ]; then
    debug "curl $url failed (rc=$rc): $(head -c 200 "$TMP/curl.err" 2>/dev/null)"
    return 2
  fi
  printf '%s\n' "$out"
  return 0
}

# --------------------------------------------------------------------------
# connectivity probes
# --------------------------------------------------------------------------
# Checking the STATUS CODE ALONE IS NOT ENOUGH: a portal that answers 200 with
# its own login HTML would look "online". We check the body too, and we do not
# follow redirects - a 3xx away from the probe URL *is* the portal talking.
#
# returns 0 = genuinely online
#         1 = intercepted (a portal answered instead of the real host)
#         2 = nothing answered at all
probe_one() {
  local url=$1 want_code=$2 want_body=$3
  local res code
  res=$(http_get "$url" "$TMP/probe.body") || return 2
  code=${res%% *}
  if [ "$code" = "$want_code" ]; then
    if [ -z "$want_body" ]; then
      # 204 must also have an empty body
      if [ ! -s "$TMP/probe.body" ]; then debug "probe $url -> clean $code"; return 0; fi
      debug "probe $url -> $code but body is non-empty ($(wc -c <"$TMP/probe.body") bytes)"
      return 1
    fi
    if grep -qiF -- "$want_body" "$TMP/probe.body"; then
      debug "probe $url -> clean $code"; return 0
    fi
  fi
  debug "probe $url -> intercepted (code=$code, $(wc -c <"$TMP/probe.body" 2>/dev/null || echo 0) bytes)"
  return 1
}

# 0 online, 1 intercepted, 2 no answer from anything
probe_internet() {
  local saw_intercept=1 line url code body
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    url=${line%%|*};        line=${line#*|}
    code=${line%%|*};       body=${line#*|}
    [ -z "$url" ] && continue
    probe_one "$url" "$code" "$body"
    case $? in
      0) return 0 ;;
      1) saw_intercept=0 ;;
    esac
  done <<< "$PROBE_URLS"
  [ $saw_intercept -eq 0 ] && return 1
  return 2
}

# NetworkManager already runs its own captive-portal detection. When it is
# present its verdict is a strong second opinion: full|portal|limited|none
nm_connectivity() {
  have nmcli || return 1
  local v
  v=$(run_limited 8 nmcli -t networking connectivity check 2>/dev/null) || return 1
  printf '%s' "$v"
}

portal_origin() {   # scheme://host:port of a URL
  local u=$1 scheme rest
  scheme=${u%%://*}; rest=${u#*://}
  printf '%s://%s' "$scheme" "${rest%%/*}"
}

portal_host_port() {
  local u=${1:-$PORTAL_URL}
  u=${u#*://}; u=${u%%/*}
  printf '%s' "$u"
}

# Is the gateway's portal listening at all?
portal_reachable() {
  local hp host port
  hp=$(portal_host_port)
  host=${hp%%:*}
  port=${hp##*:}
  [ "$port" = "$host" ] && port=80
  if have timeout && [ -e /dev/tcp ] 2>/dev/null; then :; fi
  ( exec 3<>"/dev/tcp/$host/$port" ) >/dev/null 2>&1
}

# --------------------------------------------------------------------------
# state classification
# --------------------------------------------------------------------------
# Deliberate logic, and it matters:
#   probes clean            -> ONLINE
#   probes intercepted      -> NEED_LOGIN
#   nothing answered:
#       portal answering    -> NEED_LOGIN   (pre-auth networks usually blackhole
#                                            external traffic rather than redirect)
#       portal silent       -> NETWORK_DOWN (wifi/cable problem, not a login problem)
#
# "Portal unreachable" can NOT mean "I am logged in", because if we were logged
# in the internet probes would have succeeded. Attempting a login against a dead
# network just burns failed attempts, so we refuse to.
classify() {
  local net nm
  if [ "$(lc "$TRUST_PORTAL_ONLY")" = "yes" ]; then
    if portal_reachable && portal_looks_like_login; then
      printf 'NEED_LOGIN|portal is serving a login form'; return
    fi
    printf 'ONLINE|portal is not serving a login form'; return
  fi

  probe_internet; net=$?
  case $net in
    0) printf 'ONLINE|connectivity probe returned a clean response'; return ;;
    1) printf 'NEED_LOGIN|connectivity probe was intercepted by a portal'; return ;;
  esac

  # Nothing answered on the pinned NIC. If a VPN owns the default route, that
  # can simply be its kill-switch dropping non-tunnel traffic while the machine
  # has perfectly good internet through the tunnel. Check once unpinned before
  # concluding anything - logging out on this false alarm would cut the VPN.
  if [ "$TUNNEL_DEFAULT" = yes ] && NO_PIN=1 probe_internet; then
    printf 'ONLINE|internet works through the VPN tunnel (pinned-NIC probe blocked) - nothing to do'; return
  fi

  nm=$(nm_connectivity || true)
  case "$nm" in
    portal)  printf 'NEED_LOGIN|NetworkManager reports connectivity=portal'; return ;;
    full)    printf 'ONLINE|NetworkManager reports connectivity=full (probes blocked?)'; return ;;
  esac

  if portal_reachable; then
    if portal_looks_like_login; then
      printf 'NEED_LOGIN|no internet, and the portal is serving a login form'
    else
      printf 'NEED_LOGIN|no internet, and the portal is answering'
    fi
    return
  fi
  printf 'NETWORK_DOWN|no internet and the portal at %s is not answering%s' \
         "$(portal_host_port)" "${nm:+ (nmcli: $nm)}"
}

portal_looks_like_login() {
  local res
  res=$(http_get "${LOGIN_URL:-$PORTAL_URL}" "$TMP/portal.html" --follow) || return 1
  grep -qiE 'type=["'"'"']?password|name=["'"'"']?(password|passwd|pwd)|<form' "$TMP/portal.html"
}

# --------------------------------------------------------------------------
# HTML form parsing
# --------------------------------------------------------------------------
# Bash is a poor HTML parser, so this is deliberately conservative: it splits
# the document so every tag starts a line, then pulls attributes with an awk
# helper that understands "quoted", 'quoted' and unquoted values in any order.
# Whatever it finds is printed by `inspect`, and every field can be pinned in
# the config file if the heuristics ever pick the wrong box.

AWK_ATTR='
function attr(s, a,    lo, rest, q, e) {
  lo = tolower(s)
  if (match(lo, "[[:space:]]" a "[[:space:]]*=[[:space:]]*") == 0) return ""
  rest = substr(s, RSTART + RLENGTH)
  q = substr(rest, 1, 1)
  if (q == "\"") { e = index(substr(rest, 2), "\""); return (e ? substr(rest, 2, e-1) : "") }
  if (q == "\047") { e = index(substr(rest, 2), "\047"); return (e ? substr(rest, 2, e-1) : "") }
  e = match(rest, "[[:space:]>/]")
  return (e ? substr(rest, 1, e-1) : rest)
}
'

split_tags() { tr -d '\r' < "$1" | awk '{ gsub(/</, "\n<"); print }'; }

html_unescape() {
  sed -e 's/&amp;/\&/g' -e 's/&lt;/</g' -e 's/&gt;/>/g' \
      -e 's/&quot;/"/g' -e "s/&#0*39;/'/g" -e "s/&apos;/'/g" \
      -e 's/&#0*47;/\//g' -e 's/&#x2[fF];/\//g' -e 's/&nbsp;/ /g'
}

# Isolate the <form> that actually contains a password input. Falls back to the
# whole document when the portal ships a formless / JS-driven page.
extract_login_form() {
  local src=$1 out=$2
  split_tags "$src" | awk '
    BEGIN { inf=0; haspw=0; buf=""; done=0 }
    { lo = tolower($0) }
    lo ~ /^<form/      { inf=1; haspw=0; buf=$0 "\n"; next }
    inf && lo ~ /^<\/form/ { if (haspw) { printf "%s", buf; done=1; exit } inf=0; buf=""; next }
    inf                { buf = buf $0 "\n"
                         if (lo ~ /^<input/ && lo ~ /password/) haspw=1
                         next }
    # awk runs END even after exit, so guard it or the form is emitted twice.
    END { if (!done && inf && haspw) printf "%s", buf }
  ' > "$out"
  if [ ! -s "$out" ]; then
    debug "no <form> with a password field; falling back to the whole document"
    split_tags "$src" > "$out"
  fi
}

# prints  name<TAB>value<TAB>type  for every <input> that has a name
extract_inputs() {
  split_tags "$1" | awk "$AWK_ATTR"'
    tolower($0) ~ /^<input/ {
      n = attr($0, "name"); if (n == "") next
      v = attr($0, "value")
      t = tolower(attr($0, "type")); if (t == "") t = "text"
      gsub(/\t/, " ", n); gsub(/\t/, " ", v)
      print n "\t" v "\t" t
    }'
}

form_attr() {  # form_attr <file> <action|method>
  split_tags "$1" | awk "$AWK_ATTR"'
    tolower($0) ~ /^<form/ { print attr($0, A); exit }' A="$2"
}

# resolve_url <base-page-url> <action>
resolve_url() {
  local base=$1 action=$2 scheme rest host origin path
  case "$action" in
    http://*|https://*) printf '%s' "$action"; return ;;
    '')                 printf '%s' "$base";   return ;;
  esac
  scheme=${base%%://*}
  rest=${base#*://}
  host=${rest%%/*}                         # host:port, with any path removed
  origin="$scheme://$host"
  case "$action" in
    /*) printf '%s%s' "$origin" "$action"; return ;;
  esac
  path=${rest#"$host"}                     # "/dir/file?query" or ""
  path=${path%%\?*}
  path=${path%%#*}
  path=${path%/*}
  printf '%s%s/%s' "$origin" "$path" "$action"
}

# --------------------------------------------------------------------------
# find the real login URL
# --------------------------------------------------------------------------
# This is the step naive scripts get wrong. On a FortiGate the login page is
# only valid together with a per-session "magic" token, and the gateway hands
# that token out in the redirect it sends when it intercepts your first HTTP
# request (http://<gw>:1000/fgtauth?01a2b3c4...). A bare GET of the portal root
# can yield a page with a stale or missing token, and the POST then silently
# fails. So: follow the interception first, and only fall back to the root.
discover_login_url() {
  if [ -n "$LOGIN_URL" ]; then printf '%s' "$LOGIN_URL"; return; fi

  local res redirect body_url line url code want
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    url=${line%%|*}
    res=$(http_get "$url" "$TMP/intercept.body") || continue
    code=${res%% *}
    redirect=${res##* }
    if [ -n "$redirect" ] && [ "$redirect" != "$url" ]; then
      debug "interception redirect: $redirect"
      printf '%s' "$redirect"; return
    fi
    # meta refresh / JS redirect in the interception page
    body_url=$(grep -ioE '(http-equiv=.refresh[^>]*url=|window\.location(\.href)?[[:space:]]*=[[:space:]]*.)[^"'"'"'>[:space:]]+' \
                 "$TMP/intercept.body" 2>/dev/null | head -1 |
               grep -oE 'https?://[^"'"'"'>[:space:]]+' | head -1) || true
    if [ -n "$body_url" ]; then
      debug "interception page points at: $body_url"
      printf '%s' "$body_url"; return
    fi
    break                                  # first probe that answered decides
  done <<< "$PROBE_URLS"

  debug "no interception redirect found; using the configured portal URL"
  printf '%s' "$PORTAL_URL"
}

# --------------------------------------------------------------------------
# the login itself
# --------------------------------------------------------------------------
curl_cfg_escape() {   # escape a value for a curl -K config file quoted string
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  printf '%s' "$s"
}

verify_online() {
  local i=0
  while :; do
    if probe_internet; then return 0; fi
    i=$((i+1))
    [ "$i" -ge "$VERIFY_ATTEMPTS" ] && return 1
    sleep "$VERIFY_DELAY"
  done
}

_login_attempt() {
  local forced=${1:-no}
  [ -n "$PORTAL_USERNAME" ] || { err "PORTAL_USERNAME is not set (edit $CONF_FILE)"; return 4; }
  [ -n "$PORTAL_PASSWORD" ] || { err "PORTAL_PASSWORD is not set (edit $CONF_FILE)"; return 4; }

  local page_url res code eff
  page_url=$(discover_login_url)

  # Release the session slot we already hold, BEFORE minting a token.
  #
  # Order is load-bearing. `magic` belongs to the specific intercepted
  # connection that produced it, and a logout invalidates it - so logging out
  # after scraping the token means POSTing a dead token, which a FortiGate
  # answers by silently serving the login page again. Log out first, then take
  # a fresh intercept.
  #
  # The logout matters because IIT BHU caps an account at 4 concurrent systems
  # and clearing an over-limit needs an in-person CCIS visit.
  # GUARD: never log out on a hunch.
  #
  # classify() can return NEED_LOGIN from a transient probe failure - congestion,
  # a blocked probe host, one dropped packet. Before this guard existed, that
  # produced a /logout? on a perfectly healthy link, which tears down the
  # gateway's session and kills every established connection through it,
  # including any live SSH or remote-desktop session. A self-inflicted outage,
  # once every timer tick.
  #
  # So: re-check connectivity immediately before releasing anything, and if we
  # are actually fine, do nothing at all. A forced `login` skips the guard,
  # because there the user has explicitly asked for a fresh session.
  if [ "$forced" != "force" ] && probe_internet; then
    info "connectivity is fine on re-check - not logging out, nothing to do"
    return 0
  fi

  if [ "$(lc "$LOGOUT_BEFORE_LOGIN")" = "yes" ]; then
    local origin lo_magic=""
    origin=$(portal_origin "$page_url")
    # A FortiGate logout is scoped to a session, so a bare /logout? is often a
    # no-op. The token of the session we currently hold is the query string of
    # the keepalive URL saved at our last successful login - use it when we have
    # it, and fall back to the bare form when we do not.
    load_state
    case "$KEEPALIVE_SAVED" in
      *\?*) lo_magic=${KEEPALIVE_SAVED##*\?} ;;
    esac
    if [ -n "$lo_magic" ]; then
      info "releasing the session we hold: $origin/logout?<token>"
      http_get "$origin/logout?$lo_magic" "$TMP/logout.html" >/dev/null 2>&1 || true
    else
      info "releasing any existing session: $origin/logout?"
      http_get "$origin/logout?" "$TMP/logout.html" >/dev/null 2>&1 || true
    fi
    KEEPALIVE_SAVED=""; save_state
    sleep 1
    page_url=$(discover_login_url)      # fresh intercept => fresh magic
  fi

  info "fetching login page: $page_url"

  res=$(http_get "$page_url" "$TMP/page.html" --follow) || {
    err "cannot fetch the login page at $page_url"; return 1; }
  code=${res%% *}; res=${res#* }; eff=${res%% *}
  debug "login page: HTTP $code, effective url $eff, $(wc -c <"$TMP/page.html") bytes"

  extract_login_form "$TMP/page.html" "$TMP/form.html"
  extract_inputs "$TMP/form.html" > "$TMP/inputs.tsv" || true

  # --- pick the username / password fields -------------------------------
  local pass_field=$PASS_FIELD user_field=$USER_FIELD
  if [ -z "$pass_field" ]; then
    pass_field=$(awk -F'\t' '$3=="password"{print $1; exit}' "$TMP/inputs.tsv")
  fi
  if [ -z "$pass_field" ]; then
    pass_field=$(awk -F'\t' 'tolower($1) ~ /^(password|passwd|pwd|pass)$/ {print $1; exit}' "$TMP/inputs.tsv")
  fi
  if [ -z "$user_field" ]; then
    # the named text input immediately before the password field is nearly
    # always the username; fall back to a name-based guess.
    user_field=$(awk -F'\t' -v pw="$pass_field" '
      $1==pw { print last; exit }
      $3=="text" || $3=="email" { last=$1 }' "$TMP/inputs.tsv")
  fi
  if [ -z "$user_field" ]; then
    user_field=$(awk -F'\t' 'tolower($1) ~ /user|login|uname|uid|email|account/ && $3!="hidden" {print $1; exit}' "$TMP/inputs.tsv")
  fi

  local fgt_magic=""
  if [ -z "$pass_field" ]; then
    # FortiGate sometimes serves a JS-built form. If the URL carries a magic
    # token we can still construct the canonical POST by hand.
    case "$eff$page_url" in
      *fgtauth*|*magic*)
        fgt_magic=$(printf '%s' "$eff" | sed -n 's/.*[?&]\{0,1\}\([0-9a-fA-F]\{8,\}\)$/\1/p')
        [ -z "$fgt_magic" ] && fgt_magic=$(awk -F'\t' '$1=="magic"{print $2; exit}' "$TMP/inputs.tsv")
        ;;
    esac
    if [ -n "$fgt_magic" ]; then
      warn "no password field parsed; falling back to the FortiGate field names"
      user_field=username; pass_field=password
    elif probe_internet; then
      # A FortiGate serves the login page to everything until you authenticate,
      # so "no form" plus "probes are clean" means we are already through.
      info "no login form, but connectivity is fine - already authenticated"
      return 0
    else
      err "could not find a password field on $eff - run '$APP inspect' and set USER_FIELD/PASS_FIELD in $CONF_FILE"
      cp "$TMP/page.html" "$STATE_DIR/last-page.html" 2>/dev/null || true
      return 1
    fi
  fi
  info "form fields: username=${user_field:-<none>} password=$pass_field"

  # --- build the POST ----------------------------------------------------
  local action method target
  action=$(form_attr "$TMP/form.html" action | html_unescape)
  method=$(form_attr "$TMP/form.html" method)
  target=$(resolve_url "$eff" "$action")
  info "posting credentials to $target"

  # Everything goes in a curl config file, never on the command line: argv is
  # world-readable through /proc, so -d "password=..." would leak the password
  # to every user on the box for the lifetime of the request.
  local cfg="$TMP/post.conf"
  : > "$cfg"; chmod 600 "$cfg"
  {
    printf 'data-urlencode = "%s"\n' "$(curl_cfg_escape "$user_field=$PORTAL_USERNAME")"
    printf 'data-urlencode = "%s"\n' "$(curl_cfg_escape "$pass_field=$PORTAL_PASSWORD")"
  } >> "$cfg"

  # every hidden/submit field the form ships (FortiGate: magic, 4Tredir)
  local n v t seen=""
  while IFS=$'\t' read -r n v t; do
    [ -z "$n" ] && continue
    [ "$n" = "$user_field" ] && continue
    [ "$n" = "$pass_field" ] && continue
    case "|$seen|" in *"|$n|"*) debug "skipping repeated field $n"; continue ;; esac
    case "$t" in
      hidden|submit|button)
        v=$(printf '%s' "$v" | html_unescape)
        printf 'data-urlencode = "%s"\n' "$(curl_cfg_escape "$n=$v")" >> "$cfg"
        seen="$seen|$n"
        debug "carrying form field $n=$v"
        ;;
    esac
  done < "$TMP/inputs.tsv"

  if [ -n "$fgt_magic" ] && ! grep -q 'magic=' "$cfg"; then
    printf 'data-urlencode = "%s"\n' "$(curl_cfg_escape "magic=$fgt_magic")" >> "$cfg"
    printf 'data-urlencode = "%s"\n' "$(curl_cfg_escape "4Tredir=http://www.msftconnecttest.com/connecttest.txt")" >> "$cfg"
    debug "added FortiGate magic=$fgt_magic and 4Tredir"
  fi

  if [ -n "$EXTRA_FIELDS" ]; then
    local pair
    IFS='&' read -ra _extra <<< "$EXTRA_FIELDS"
    for pair in "${_extra[@]}"; do
      [ -z "$pair" ] && continue
      printf 'data-urlencode = "%s"\n' "$(curl_cfg_escape "$pair")" >> "$cfg"
    done
  fi

  curl_opts; local opts=( "${CURL_ARGS[@]}" )
  opts+=( --location --max-redirs 10 -K "$cfg"
          -b "$COOKIE_JAR" -c "$COOKIE_JAR" --referer "$eff" )
  [ "$(lc "$method")" = "get" ] && opts+=( --get )

  local out rc
  out=$(curl "${opts[@]}" -o "$TMP/result.html" -w '%{http_code}' "$target" 2>"$TMP/curl.err")
  rc=$?
  rm -f "$cfg"
  if [ $rc -ne 0 ]; then
    err "login POST failed (curl rc=$rc): $(head -c 200 "$TMP/curl.err")"
    return 1
  fi
  debug "login POST -> HTTP $out, $(wc -c <"$TMP/result.html") bytes"

  # --- read the answer ---------------------------------------------------
  local low
  low=$(tr 'A-Z' 'a-z' < "$TMP/result.html" | tr -d '\n' | head -c 20000)
  case "$low" in
    *"firewall authentication failed"*|*"authentication failed"*|*"invalid username"*|\
    *"invalid credentials"*|*"login failed"*|*"incorrect password"*|*"wrong password"*)
      err "the portal rejected these credentials - check PORTAL_USERNAME / PORTAL_PASSWORD"
      cp "$TMP/result.html" "$STATE_DIR/last-result.html" 2>/dev/null || true
      return 5 ;;                        # 5 = do not retry quickly, it is the password
    *"already logged in"*|*"concurrent"*|*"maximum number of"*|*"session limit"*)
      warn "the portal says this account is already logged in elsewhere" ;;
  esac

  if verify_online; then
    info "LOGIN OK - internet is reachable again"
    # The gateway hands back a keepalive URL. Holding it refreshes the session
    # without creating a new one, which is exactly what the institute's own
    # wired-setup guide tells users to do ("refrain from closing this dialog").
    local ka cd
    ka=$(grep -oE "https?://[^\"' >]*keepalive[^\"' >]*" "$TMP/result.html" 2>/dev/null | head -1)
    if [ -n "$ka" ]; then
      KEEPALIVE_SAVED=$ka
      info "keepalive URL captured"
      cd=$(grep -oE 'countDownTime[^0-9]*[0-9]+' "$TMP/result.html" 2>/dev/null |
           grep -oE '[0-9]+' | head -1)
      [ -n "$cd" ] && info "portal reports countDownTime=$cd (session is about $((cd * 3 / 60)) minutes)"
    fi
    return 0
  fi

  # The signature FortiGate failure: HTTP 200 and the login form all over
  # again, with no error text anywhere. Almost always a stale/rejected token.
  if grep -qiE 'type=["'"'"']?password|name=["'"'"']?magic' "$TMP/result.html" 2>/dev/null; then
    warn "the portal answered with its login page again rather than authenticating"
    cp "$TMP/result.html" "$STATE_DIR/last-result.html" 2>/dev/null || true
    return 6
  fi

  err "login was submitted but connectivity did not come back"
  cp "$TMP/result.html" "$STATE_DIR/last-result.html" 2>/dev/null || true
  return 1
}

# One retry with a freshly minted token, then give up with a real diagnosis.
do_login() {
  local forced=${1:-no} rc
  _login_attempt "$forced"; rc=$?
  if [ "$rc" -eq 6 ]; then
    warn "retrying once with a freshly minted token"
    sleep 2
    _login_attempt "$forced"; rc=$?
  fi
  if [ "$rc" -eq 6 ]; then
    err "the portal keeps returning its login page. In order of likelihood:"
    err "  1. wrong username or password  -> check $CONF_FILE"
    err "  2. the account is at its 4-system concurrent limit"
    err "  3. the form wants a field we are not sending -> run '$APP inspect'"
    err "  the portal's own reply is saved at $STATE_DIR/last-result.html"
    rc=1
  fi
  return $rc
}

# --------------------------------------------------------------------------
# state + backoff
# --------------------------------------------------------------------------
FAILS=0; NEXT_ATTEMPT=0; LAST_OK=0; LAST_STATE=""; OFFLINE_SINCE=0; KEEPALIVE_SAVED=""

load_state() {
  [ -f "$STATE_FILE" ] || return 0
  local k v
  while IFS='=' read -r k v; do
    case "$k" in
      FAILS|NEXT_ATTEMPT|LAST_OK|LAST_STATE|OFFLINE_SINCE|KEEPALIVE_SAVED)
        printf -v "$k" '%s' "$v" ;;
    esac
  done < "$STATE_FILE"
  return 0
}

save_state() {
  { printf 'FAILS=%s\n' "$FAILS"
    printf 'NEXT_ATTEMPT=%s\n' "$NEXT_ATTEMPT"
    printf 'LAST_OK=%s\n' "$LAST_OK"
    printf 'LAST_STATE=%s\n' "$LAST_STATE"
    printf 'OFFLINE_SINCE=%s\n' "$OFFLINE_SINCE"
    printf 'KEEPALIVE_SAVED=%s\n' "$KEEPALIVE_SAVED"
  } > "$STATE_FILE.tmp" 2>/dev/null && mv -f "$STATE_FILE.tmp" "$STATE_FILE" 2>/dev/null
  return 0
}

fire_alert() {
  [ -n "$ALERT_COMMAND" ] || return 0
  info "running ALERT_COMMAND"
  PORTAL_STATE="$1" PORTAL_MESSAGE="$2" PORTAL_HOST="$(box_name)" \
    run_limited 30 sh -c "$ALERT_COMMAND" >/dev/null 2>&1 || warn "ALERT_COMMAND failed"
}

# --------------------------------------------------------------------------
# one pass
# --------------------------------------------------------------------------
run_once() {
  local force=${1:-no}
  local now state reason c rc delay
  now=$(date +%s)
  load_state

  if [ "$force" = "force" ]; then
    state=NEED_LOGIN; reason="forced"
  else
    c=$(classify); state=${c%%|*}; reason=${c#*|}
  fi
  info "state=$state ($reason)"

  case "$state" in
    ONLINE)
      [ "$FAILS" -gt 0 ] 2>/dev/null && info "clearing $FAILS recorded failure(s)"
      FAILS=0; NEXT_ATTEMPT=0; LAST_OK=$now; LAST_STATE=ONLINE; OFFLINE_SINCE=0
      save_state
      # Refreshing the existing session costs no concurrent slot; a fresh login
      # costs one. Poke it on every healthy check.
      local ka=${KEEPALIVE_URL:-$KEEPALIVE_SAVED}
      if [ -n "$ka" ] && [ "$(lc "$KEEPALIVE_ENABLED")" = "yes" ]; then
        http_get "$ka" "$TMP/ka.body" >/dev/null 2>&1 && debug "keepalive refreshed"
      fi
      # Dead-man's switch: alerting ON failure cannot work, because a failure
      # means no internet to alert over. Ping while healthy instead and let the
      # silence be the alarm (healthchecks.io, or ntfy with a scheduled check).
      if [ -n "$HEARTBEAT_URL" ]; then
        http_get "$HEARTBEAT_URL" "$TMP/hb.body" --follow >/dev/null 2>&1 \
          && debug "heartbeat sent"
      fi
      return 0 ;;

    NETWORK_DOWN)
      LAST_STATE=NETWORK_DOWN
      [ "$OFFLINE_SINCE" = "0" ] && OFFLINE_SINCE=$now
      save_state
      local mins=$(( (now - OFFLINE_SINCE) / 60 ))
      warn "the network itself looks down (${mins}m) - not attempting a login"
      if [ "${REBOOT_AFTER_OFFLINE_MIN:-0}" -gt 0 ] 2>/dev/null && [ "$mins" -ge "$REBOOT_AFTER_OFFLINE_MIN" ]; then
        err "offline for ${mins}m >= REBOOT_AFTER_OFFLINE_MIN - rebooting"
        fire_alert NETWORK_DOWN "offline ${mins}m, rebooting $(box_name)"
        OFFLINE_SINCE=0; save_state
        systemctl reboot || reboot
      fi
      return 2 ;;
  esac

  # NEED_LOGIN
  if [ "$force" != "force" ] && [ "$now" -lt "${NEXT_ATTEMPT:-0}" ] 2>/dev/null; then
    warn "backing off after $FAILS failure(s); next attempt in $((NEXT_ATTEMPT - now))s"
    return 3
  fi

  do_login "$force"; rc=$?
  case $rc in
    0)
      FAILS=0; NEXT_ATTEMPT=0; LAST_OK=$(date +%s); LAST_STATE=ONLINE; OFFLINE_SINCE=0
      save_state
      [ "$force" = "force" ] || fire_alert ONLINE "re-authenticated $(box_name)"
      return 0 ;;
    4)
      return 4 ;;
    5)
      # Bad credentials. Back off HARD - hammering the portal with a wrong
      # password is how accounts get locked out.
      FAILS=$((FAILS + 1))
      NEXT_ATTEMPT=$(( $(date +%s) + BACKOFF_MAX ))
      LAST_STATE=NEED_LOGIN; save_state
      err "credentials rejected; not retrying for ${BACKOFF_MAX}s"
      fire_alert BAD_CREDENTIALS "portal rejected the password on $(box_name)"
      return 1 ;;
    *)
      FAILS=$((FAILS + 1))
      delay=$BACKOFF_BASE
      local i=1
      while [ "$i" -lt "$FAILS" ] && [ "$delay" -lt "$BACKOFF_MAX" ]; do
        delay=$((delay * 2)); i=$((i + 1))
      done
      [ "$delay" -gt "$BACKOFF_MAX" ] && delay=$BACKOFF_MAX
      NEXT_ATTEMPT=$(( $(date +%s) + delay ))
      LAST_STATE=NEED_LOGIN; save_state
      err "login failed ($FAILS in a row); next attempt in ${delay}s"
      [ "$FAILS" -eq "${ALERT_AFTER_FAILURES:-3}" ] 2>/dev/null && \
        fire_alert LOGIN_FAILED "$FAILS failed portal logins on $(box_name)"
      return 1 ;;
  esac
}

# Tell systemd we are still alive. If the loop ever wedges (a curl that hangs
# past its own --max-time, a stuck DNS resolver), systemd kills and restarts us
# rather than leaving a process that exists but does nothing - which is the
# failure mode a plain "Restart=always" cannot catch.
wd_ping() {
  [ -n "${WATCHDOG_USEC:-}" ] || return 0
  have systemd-notify && systemd-notify WATCHDOG=1 2>/dev/null
  return 0
}

# Sleep in short chunks, pinging the watchdog as we go, so WatchdogSec can stay
# tight no matter how long CHECK_INTERVAL is.
wd_sleep() {
  local left=$1 chunk
  while [ "$left" -gt 0 ]; do
    chunk=$(( left > 20 ? 20 : left ))
    sleep "$chunk"
    left=$(( left - chunk ))
    wd_ping
  done
}

run_daemon() {
  info "daemon mode: checking every ${CHECK_INTERVAL}s (+/-${JITTER}s)"
  [ -n "${WATCHDOG_USEC:-}" ] && info "systemd watchdog active (${WATCHDOG_USEC}us)"
  trap 'info "stopping on signal"; exit 0' INT TERM
  local nap
  while :; do
    run_once || true
    wd_ping
    nap=$(( CHECK_INTERVAL - JITTER + (RANDOM % (2 * JITTER + 1)) ))
    [ "$nap" -lt 30 ] && nap=30
    debug "sleeping ${nap}s"
    wd_sleep "$nap"
  done
}

# --------------------------------------------------------------------------
# inspect
# --------------------------------------------------------------------------
do_inspect() {
  local page_url res code eff
  page_url=$(discover_login_url)
  printf '\nportal URL      : %s\n' "$PORTAL_URL"
  printf 'discovered URL  : %s\n' "$page_url"

  res=$(http_get "$page_url" "$TMP/page.html" --follow) || {
    printf '\ncould not fetch that page. Are you on the campus network?\n\n'; return 1; }
  code=${res%% *}; res=${res#* }; eff=${res%% *}
  printf 'effective URL   : %s\nHTTP status     : %s\nbytes           : %s\n\n' \
         "$eff" "$code" "$(wc -c <"$TMP/page.html")"

  extract_login_form "$TMP/page.html" "$TMP/form.html"
  printf 'form action     : %s\nform method     : %s\n\n' \
         "$(form_attr "$TMP/form.html" action)" "$(form_attr "$TMP/form.html" method)"

  extract_inputs "$TMP/form.html" > "$TMP/inputs.tsv" || true
  printf '%-26s %-10s %s\n' NAME TYPE VALUE
  printf '%s\n' "--------------------------------------------------------------------------"
  awk -F'\t' '{ printf "%-26s %-10s %s\n", $1, $3, (tolower($3)=="password" ? "***" : substr($2,1,40)) }' \
      "$TMP/inputs.tsv"

  local pf uf
  pf=$(awk -F'\t' '$3=="password"{print $1; exit}' "$TMP/inputs.tsv")
  uf=$(awk -F'\t' -v pw="$pf" '$1==pw{print last; exit} $3=="text"||$3=="email"{last=$1}' "$TMP/inputs.tsv")
  printf '\nauto-detected   : USER_FIELD=%s  PASS_FIELD=%s\n' "${uf:-<none>}" "${pf:-<none>}"
  printf 'If those are wrong, pin them in %s\n\n' "$CONF_FILE"
  cp "$TMP/page.html" "$STATE_DIR/last-page.html" 2>/dev/null && \
    printf 'raw page saved to %s\n\n' "$STATE_DIR/last-page.html"
  return 0
}

# --------------------------------------------------------------------------
# install / uninstall / harden / status
# --------------------------------------------------------------------------
INSTALL_MODE=timer        # timer | daemon  (see: install --daemon)
if [ "$IS_MAC" = yes ]; then
  BIN_PATH="${PORTAL_LOGIN_BIN:-/usr/local/bin/$APP}"   # /usr/local/sbin does not exist on macOS
else
  BIN_PATH="${PORTAL_LOGIN_BIN:-/usr/local/sbin/$APP}"
fi
UNIT_DIR=/etc/systemd/system
DISPATCH=/etc/NetworkManager/dispatcher.d/90-$APP
# macOS / launchd
PLIST_DIR="${PORTAL_LOGIN_PLIST_DIR:-/Library/LaunchDaemons}"
LABEL_CHECK=com.portal-login.check
LABEL_DAEMON=com.portal-login.daemon
LABEL_NETWATCH=com.portal-login.netwatch
MAC_LOG=/var/log/$APP.log
NEWSYSLOG_CONF=/etc/newsyslog.d/$APP.conf
RUN_AS=""                 # human summary of how it was installed, set by do_install

need_root() { [ "$(id -u)" -eq 0 ] || die "this command needs root: sudo $APP $1"; }

write_config_template() {
  cat > "$1" <<'CONF_EOF'
# portal-login configuration.            chmod 600 - this file holds a password.
#
# Format is KEY = VALUE, one per line. The file is PARSED, not executed, so any
# character is safe in a password. Everything after the first '=' is taken
# literally to the end of the line; wrap the value in quotes to keep leading or
# trailing spaces. Comments must be on their own line.

# ---- credentials ---------------------------------------------------------
PORTAL_URL      = http://192.168.252.1:1000/
PORTAL_USERNAME =
PORTAL_PASSWORD =

# ---- form fields ---------------------------------------------------------
# Leave blank to auto-detect. Run `portal-login inspect` to see the real names
# and pin them here if auto-detection ever picks the wrong box.
USER_FIELD =
PASS_FIELD =
# LOGIN_URL    = http://192.168.252.1:1000/fgtauth
# EXTRA_FIELDS = realm=students&lang=en

# ---- behaviour -----------------------------------------------------------
# auto = pin every request to the physical NIC holding the default route.
# Leave this on "auto". If you install Tailscale/WireGuard later, an unpinned
# probe can start egressing through the tunnel and report "online" forever while
# the campus session is actually dead. "any" disables pinning; a name pins it.
INTERFACE  = auto
FORCE_IPV4 = yes

# Release the session slot before taking a new one. IIT BHU allows 4 systems per
# account and clearing a "Concurrent Over-limit" requires visiting CCIS in
# person with an ID card - so do not turn this off.
LOGOUT_BEFORE_LOGIN = yes

# Refresh the existing session instead of making a new one. Costs no slot.
KEEPALIVE_ENABLED = yes
# KEEPALIVE_URL   =        # normally captured automatically after a login

# Dead-man's switch. Alerting when things BREAK cannot work - a break means no
# internet to alert over. Ping this while healthy and let silence be the alarm.
# Free option: make a check at https://healthchecks.io and paste its ping URL.
HEARTBEAT_URL = 

# After a failed login, wait this long and double each time, up to the max.
# This is what stops a wrong password from locking your account out overnight.
BACKOFF_BASE = 300
BACKOFF_MAX  = 3600

CONNECT_TIMEOUT = 5
MAX_TIME        = 15
VERIFY_ATTEMPTS = 6
VERIFY_DELAY    = 3

# daemon mode only - the systemd timer carries its own interval
CHECK_INTERVAL = 300
JITTER         = 30

# Connectivity probes. Repeat the key to use several; the first one that
# answers decides. Format: <url>|<expected status>|<expected body substring>
# Only override these if your campus blocks the defaults even while you ARE online.
# PROBE = http://connectivitycheck.gstatic.com/generate_204|204|
# PROBE = http://detectportal.firefox.com/success.txt|200|success

# ---- alerting (optional) -------------------------------------------------
# Runs on repeated failure. $PORTAL_STATE / $PORTAL_MESSAGE / $PORTAL_HOST are
# exported for it. A free ntfy.sh topic is the easiest phone notification:
# ALERT_COMMAND = curl -s -d "$PORTAL_MESSAGE" https://ntfy.sh/pick-a-secret-topic
ALERT_COMMAND        =
ALERT_AFTER_FAILURES = 3

# ---- last resort ---------------------------------------------------------
# Reboot if the network has been *down* (not just logged out) this many minutes.
# 0 disables it. Only enable this if you are sure nothing important is running.
REBOOT_AFTER_OFFLINE_MIN = 0

# ---- logging -------------------------------------------------------------
LOG_LEVEL = info
# LOG_FILE = /var/log/portal-login.log     # blank = journald only
CONF_EOF
  chmod 600 "$1"
}

write_daemon_unit() {
  cat > "$UNIT_DIR/$APP.service" <<DSVC_EOF
[Unit]
Description=Captive portal auto-login (always-on daemon)
After=network-online.target
Wants=network-online.target
# Never stop trying. Without this, systemd gives up after 5 restarts in 10s and
# the box stays offline until a human intervenes - the exact opposite of the point.
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=$BIN_PATH daemon
Restart=always
RestartSec=30
# The daemon reports liveness from a helper process, so notifications from any
# pid in the cgroup must be accepted.
NotifyAccess=all
WatchdogSec=300
Nice=10
StateDirectory=$APP
StateDirectoryMode=0700
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
DSVC_EOF
}

# --------------------------------------------------------------------------
# macOS: launchd
# --------------------------------------------------------------------------
# A LaunchDaemon (in /Library/LaunchDaemons, root:wheel 644) runs as root with
# nobody logged in and is started by launchd at boot - the direct equivalent
# of a root systemd unit. StartInterval gives the 5-minute cadence, RunAtLoad
# the run-at-boot; KeepAlive is deliberately absent on the periodic job, since
# launchd would otherwise respawn a oneshot the moment it exits.
plist_header() {
  cat <<'PH'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
PH
}

write_plist_check() {     # $1 = path
  { plist_header; cat <<PC
  <key>Label</key><string>$LABEL_CHECK</string>
  <key>ProgramArguments</key>
  <array><string>$BIN_PATH</string><string>once</string></array>
  <key>StartInterval</key><integer>300</integer>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>Nice</key><integer>10</integer>
  <key>StandardOutPath</key><string>$MAC_LOG</string>
  <key>StandardErrorPath</key><string>$MAC_LOG</string>
</dict>
</plist>
PC
  } > "$1"
}

write_plist_daemon() {    # $1 = path
  { plist_header; cat <<PD
  <key>Label</key><string>$LABEL_DAEMON</string>
  <key>ProgramArguments</key>
  <array><string>$BIN_PATH</string><string>daemon</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ProcessType</key><string>Background</string>
  <key>Nice</key><integer>10</integer>
  <key>StandardOutPath</key><string>$MAC_LOG</string>
  <key>StandardErrorPath</key><string>$MAC_LOG</string>
</dict>
</plist>
PD
  } > "$1"
}

# The macOS counterpart of the NetworkManager hook: configd rewrites
# resolv.conf on every network change (join wifi, plug in ethernet, DHCP
# renew), so watching it fires a check the moment the link changes.
write_plist_netwatch() {  # $1 = path
  { plist_header; cat <<PN
  <key>Label</key><string>$LABEL_NETWATCH</string>
  <key>ProgramArguments</key>
  <array><string>$BIN_PATH</string><string>once</string></array>
  <key>WatchPaths</key>
  <array>
    <string>/private/var/run/resolv.conf</string>
    <string>/Library/Preferences/SystemConfiguration</string>
  </array>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>$MAC_LOG</string>
  <key>StandardErrorPath</key><string>$MAC_LOG</string>
</dict>
</plist>
PN
  } > "$1"
}

launchd_load() {          # $1 = label
  # bootstrap refuses an already-loaded job, so unload first (ignore failure)
  launchctl bootout "system/$1" >/dev/null 2>&1 || true
  launchctl enable "system/$1" >/dev/null 2>&1 || true
  launchctl bootstrap system "$PLIST_DIR/$1.plist"
}

launchd_unload() {        # $1 = label
  launchctl bootout "system/$1" >/dev/null 2>&1 || true
  rm -f "$PLIST_DIR/$1.plist"
}

install_launchd() {
  install -d -m 0755 "$PLIST_DIR"
  touch "$MAC_LOG" 2>/dev/null; chmod 644 "$MAC_LOG" 2>/dev/null || true

  if [ "$INSTALL_MODE" = daemon ]; then
    launchd_unload "$LABEL_CHECK"
    write_plist_daemon "$PLIST_DIR/$LABEL_DAEMON.plist"
    chown root:wheel "$PLIST_DIR/$LABEL_DAEMON.plist"; chmod 644 "$PLIST_DIR/$LABEL_DAEMON.plist"
    launchd_load "$LABEL_DAEMON" && echo "  ok  launchd daemon loaded ($LABEL_DAEMON) - always running, restarts itself, starts at boot"
    RUN_AS="a launchd daemon (always running, restarts itself, starts at boot)"
  else
    launchd_unload "$LABEL_DAEMON"
    write_plist_check "$PLIST_DIR/$LABEL_CHECK.plist"
    chown root:wheel "$PLIST_DIR/$LABEL_CHECK.plist"; chmod 644 "$PLIST_DIR/$LABEL_CHECK.plist"
    launchd_load "$LABEL_CHECK" && echo "  ok  launchd job loaded ($LABEL_CHECK) - every 5 minutes, and at boot"
    RUN_AS="a launchd job every 5 min (also runs at boot)"
  fi

  write_plist_netwatch "$PLIST_DIR/$LABEL_NETWATCH.plist"
  chown root:wheel "$PLIST_DIR/$LABEL_NETWATCH.plist"; chmod 644 "$PLIST_DIR/$LABEL_NETWATCH.plist"
  launchd_load "$LABEL_NETWATCH" && echo "  ok  network-change hook loaded ($LABEL_NETWATCH)"

  # rotate the log so it cannot grow forever
  if [ -d /etc/newsyslog.d ]; then
    printf '# logfilename                  [owner:group]  mode count size when flags\n%s  644  5  1024  *  JN\n' \
      "$MAC_LOG" > "$NEWSYSLOG_CONF"
    echo "  ok  log rotation configured ($NEWSYSLOG_CONF)"
  fi
}

uninstall_launchd() {
  launchd_unload "$LABEL_CHECK"
  launchd_unload "$LABEL_DAEMON"
  launchd_unload "$LABEL_NETWATCH"
  rm -f "$NEWSYSLOG_CONF"
  echo "  ok  launchd jobs removed"
}

status_launchd() {
  local l
  for l in "$LABEL_DAEMON" "$LABEL_CHECK"; do
    if launchctl print "system/$l" >/dev/null 2>&1; then
      if [ "$l" = "$LABEL_DAEMON" ]; then printf 'mode   : launchd daemon (always running)\n'
      else printf 'mode   : launchd job every 5 min\n'; fi
      launchctl print "system/$l" 2>/dev/null |
        grep -E 'state = |last exit code|run interval|runs = |pid = ' | sed 's/^[[:space:]]*/         /'
      printf '\n'
      break
    fi
  done
  launchctl print "system/$LABEL_CHECK"  >/dev/null 2>&1 || \
  launchctl print "system/$LABEL_DAEMON" >/dev/null 2>&1 || \
    printf 'mode   : NOT INSTALLED - run: sudo %s install\n\n' "$APP"
  launchctl print "system/$LABEL_NETWATCH" >/dev/null 2>&1 && printf 'hook   : network-change watcher loaded\n\n'
  [ -f "$MAC_LOG" ] && { printf -- '-- last 20 log lines (%s) --\n' "$MAC_LOG"; tail -20 "$MAC_LOG"; }
}

confirm_proceed() {
  if [ "${ASSUME_YES:-no}" = "yes" ]; then return 0; fi
  if [ -t 0 ]; then
    printf 'proceed? [y/N] '; read -r ans
    case "$(lc "$ans")" in y|yes) return 0 ;; *) echo "aborted."; return 1 ;; esac
  fi
  die "not a terminal - re-run with: $APP harden --yes"
}

harden_mac() {
  cat <<'PLAN'

'harden' makes this Mac survive an unattended night. It will:

  1. pmset -c sleep 0 disksleep 0     -> never sleep while on mains power
  2. pmset -a womp 1                  -> wake on LAN
  3. pmset -a tcpkeepalive 1          -> keep TCP sessions alive in low-power states

Only the on-charger (-c) profile is changed, so a laptop on battery still
sleeps normally. Undo notes are printed at the end.

PLAN
  confirm_proceed || return 0
  pmset -c sleep 0 disksleep 0 2>/dev/null && echo "  ok  no sleep on mains power"
  pmset -a womp 1 2>/dev/null          && echo "  ok  wake on LAN"
  pmset -a tcpkeepalive 1 2>/dev/null  && echo "  ok  tcp keepalive"
  cat <<'UNDO'

  A closed MacBook still sleeps (clamshell) unless it is on power AND has an
  external display or keyboard attached. Leave the lid open, or use a
  display dummy plug, if the machine is a laptop.

  macOS also has its own captive-portal assistant that opens a login window.
  It does not interfere with this tool. (The old
  com.apple.captive.control Active=false trick is unreliable on recent macOS.)

  There is no network-online wait in launchd: the run at boot may happen before
  DHCP finishes and will correctly report NETWORK_DOWN; the network-change job
  and the 5-minute tick pick it up seconds later.

  To undo:  sudo pmset -c restoredefaults ; sudo pmset -a womp 0

UNDO
}

do_install() {
  need_root install
  have curl || die "curl is required: sudo apt install -y curl  (or dnf/pacman)"
  if ! have flock; then
    [ "$IS_MAC" = yes ] && debug "no flock on macOS - using the mkdir lock" \
                        || warn "flock not found (util-linux); falling back to a mkdir lock"
  fi

  # BUG FIX: the destination directory is not guaranteed to exist (macOS has
  # no /usr/local/sbin), and a failed copy used to be reported as success.
  install -d -m 0755 "$(dirname "$BIN_PATH")" || die "cannot create $(dirname "$BIN_PATH")"
  if [ "$IS_MAC" = yes ]; then
    # A script downloaded through a browser carries com.apple.quarantine and
    # Gatekeeper refuses to execute it. git/scp/curl do not set it; clear it anyway.
    xattr -d com.apple.quarantine "$SELF" >/dev/null 2>&1 || true
    # Homebrew on Intel chowns /usr/local/bin to the user; a root daemon must
    # not execute a user-writable file.
    install -o root -g wheel -m 0755 "$SELF" "$BIN_PATH" || die "failed to install $BIN_PATH"
  else
    install -m 0755 "$SELF" "$BIN_PATH" || die "failed to install $BIN_PATH"
  fi
  [ -x "$BIN_PATH" ] || die "$BIN_PATH is not executable after install"
  echo "  ok  installed $BIN_PATH"

  install -d -m 0700 "$(dirname "$CONF_FILE")"
  if [ -f "$CONF_FILE" ]; then
    chmod 600 "$CONF_FILE"
    echo "  ok  kept existing config $CONF_FILE"
  else
    write_config_template "$CONF_FILE"
    echo "  ok  created $CONF_FILE (mode 600)"
  fi
  install -d -m 0700 "$STATE_DIR"

  if [ "$IS_MAC" = yes ]; then
    install_launchd
  elif have systemctl && [ -d /run/systemd/system ]; then
   if [ "$INSTALL_MODE" = daemon ]; then
    # switching modes: make sure the timer is not also running
    systemctl disable --now "$APP.timer" >/dev/null 2>&1 || true
    rm -f "$UNIT_DIR/$APP.timer"
    write_daemon_unit
    systemctl daemon-reload
    systemctl enable --now "$APP.service" >/dev/null
    echo "  ok  always-on daemon enabled (checks every ${CHECK_INTERVAL}s, restarts itself, starts at boot)"
    RUN_AS="an always-on systemd daemon (auto-restarts, starts at boot)"
   else
    # switching modes: make sure a daemon is not also running
    systemctl disable --now "$APP.service" >/dev/null 2>&1 || true
    cat > "$UNIT_DIR/$APP.service" <<SVC_EOF
[Unit]
Description=Captive portal auto-login (re-authenticate when the session expires)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=$BIN_PATH once
# For Type=oneshot systemd DISABLES the start timeout by default, so a curl stuck
# in a half-open connection would park this unit in "activating" forever and the
# timer would never fire again. Set it explicitly, and give SIGKILL a deadline.
TimeoutStartSec=90
TimeoutStopSec=20
# 1=login failed 2=network down 3=backing off 4=misconfigured. All are expected
# outcomes the script already schedules its own retry for - they must not look
# like crashes, or systemd restarts on top of our backoff.
SuccessExitStatus=1 2 3 4
# on-abnormal = restart only on a signal/timeout/watchdog kill, i.e. exactly the
# hung-curl case above. (always/on-success are the only values oneshot rejects.)
Restart=on-abnormal
RestartSec=30
Nice=10
StateDirectory=$APP
StateDirectoryMode=0700
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SVC_EOF

    cat > "$UNIT_DIR/$APP.timer" <<TIMER_EOF
[Unit]
Description=Re-check the captive portal login every 5 minutes

[Timer]
OnBootSec=90s
OnUnitActiveSec=5min
AccuracySec=15s
RandomizedDelaySec=30s
Persistent=true
Unit=$APP.service

[Install]
WantedBy=timers.target
TIMER_EOF

    systemctl daemon-reload
    systemctl enable --now "$APP.timer" >/dev/null
    echo "  ok  systemd timer enabled (every 5 minutes, and 90s after every boot)"
    RUN_AS="a systemd timer every 5 min (also starts 90s after boot)"
   fi

    # network-online.target is a no-op unless a wait-online service is enabled
    if systemctl list-unit-files 2>/dev/null | grep -q '^NetworkManager-wait-online\.service'; then
      systemctl enable NetworkManager-wait-online.service >/dev/null 2>&1 && \
        echo "  ok  NetworkManager-wait-online enabled"
    elif systemctl list-unit-files 2>/dev/null | grep -q '^systemd-networkd-wait-online\.service'; then
      systemctl enable systemd-networkd-wait-online.service >/dev/null 2>&1 && \
        echo "  ok  systemd-networkd-wait-online enabled"
    fi
  else
    warn "no systemd - falling back to cron"
    ( crontab -l 2>/dev/null | grep -v "$APP" ; echo "*/5 * * * * $BIN_PATH once >/dev/null 2>&1" ) | crontab -
    echo "  ok  crontab entry added (every 5 minutes)"
    RUN_AS="a cron job every 5 min (no systemd on this box)"
  fi

  # Fire immediately when a link comes up, instead of waiting up to 5 minutes.
  if [ -d /etc/NetworkManager/dispatcher.d ]; then
    cat > "$DISPATCH" <<DISP_EOF
#!/bin/sh
# \$1 = interface, \$2 = action. Kick the portal check the moment a link is up.
case "\$2" in
  up|dhcp4-change|dhcp6-change|connectivity-change)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl --no-block start $APP.service
    else
      ($BIN_PATH once >/dev/null 2>&1 &)
    fi
    ;;
esac
exit 0
DISP_EOF
    chown root:root "$DISPATCH"; chmod 0755 "$DISPATCH"
    echo "  ok  NetworkManager hook installed ($DISPATCH)"
  fi

  cat <<DONE

running as: ${RUN_AS:-unknown}

next steps
  1. credentials:   sudo nano $CONF_FILE
  2. see the form:  sudo $APP inspect
  3. test it:       sudo $APP check       # just report the state
                    sudo $APP login -v    # force one login, verbose
  4. watch it:      sudo $APP status
                    $([ "$IS_MAC" = yes ] && echo "tail -f $MAC_LOG" || echo "journalctl -u $APP -f")
  5. optional:      sudo $APP harden      # no suspend, no wifi powersave

DONE
}

do_uninstall() {
  need_root uninstall
  if [ "$IS_MAC" = yes ]; then
    uninstall_launchd
  elif have systemctl; then
    systemctl disable --now "$APP.timer" >/dev/null 2>&1 || true
    systemctl disable --now "$APP.service" >/dev/null 2>&1 || true
    rm -f "$UNIT_DIR/$APP.service" "$UNIT_DIR/$APP.timer"
    systemctl daemon-reload || true
    echo "  ok  systemd units removed"
  fi
  if have crontab && crontab -l 2>/dev/null | grep -q "$APP"; then
    crontab -l 2>/dev/null | grep -v "$APP" | crontab -
    echo "  ok  crontab entry removed"
  fi
  rm -f "$DISPATCH" "$BIN_PATH"
  echo "  ok  removed $BIN_PATH and the NetworkManager hook"
  echo "  !!  kept your config: $CONF_FILE"
  echo "  !!  kept your state:  $STATE_DIR"
}

do_harden() {
  need_root harden
  if [ "$IS_MAC" = yes ]; then harden_mac; return $?; fi
  cat <<PLAN

'harden' makes this machine survive an unattended night. It will:

  1. mask sleep.target suspend.target hibernate.target hybrid-sleep.target
     -> the box can never suspend itself while you are away
  2. set logind IdleAction=ignore and HandleLidSwitch=ignore
  3. turn off wifi power saving (NetworkManager wifi.powersave=2)
     -> a very common cause of "it was fine and then it just dropped at 2am"
  4. set every NetworkManager connection to autoconnect with infinite retries

These are system-wide and persist across reboots. Undo notes are printed at the end.

PLAN
  confirm_proceed || return 0

  systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target >/dev/null 2>&1 \
    && echo "  ok  suspend/hibernate masked"

  install -d -m 0755 /etc/systemd/logind.conf.d
  cat > /etc/systemd/logind.conf.d/99-$APP.conf <<'LOGIND_EOF'
[Login]
IdleAction=ignore
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
HandleLidSwitchDocked=ignore
LOGIND_EOF
  echo "  ok  logind: idle and lid actions ignored"

  if [ -d /etc/NetworkManager/conf.d ]; then
    cat > /etc/NetworkManager/conf.d/99-$APP-powersave.conf <<'NMPS_EOF'
[connection]
wifi.powersave = 2
NMPS_EOF
    echo "  ok  wifi power saving disabled"
  fi

  if have nmcli; then
    nmcli -t -f NAME connection show 2>/dev/null | while IFS= read -r cn; do
      [ -z "$cn" ] && continue
      nmcli connection modify "$cn" connection.autoconnect yes \
            connection.autoconnect-retries 0 >/dev/null 2>&1 \
        && echo "  ok  autoconnect (infinite retries) on '$cn'"
    done
  fi

  # GNOME's screen blanking is a per-user gsettings value, so a root-level
  # harden cannot reach it. It defaults to 5 minutes and regularly takes a
  # remote-desktop session down with it, which looks exactly like a network drop.
  cat <<'GS'

  ONE MORE THING, and root cannot do it for you:

  GNOME blanks the screen after 5 minutes by default, which can drop an AnyDesk
  or VNC session. logind's IdleAction (set above) does NOT cover this. Run these
  as your normal desktop user, in a terminal ON the machine's own desktop:

    gsettings set org.gnome.desktop.session idle-delay 0
    gsettings set org.gnome.desktop.screensaver idle-activation-enabled false
    gsettings set org.gnome.desktop.screensaver lock-enabled false
    gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type 'nothing'

  Check the current value with:
    gsettings get org.gnome.desktop.session idle-delay      # uint32 300 = 5 min
GS

  cat <<'UNDO'

  APPLYING THESE:

    wifi powersave:  sudo systemctl reload NetworkManager
                     (reload re-reads the config WITHOUT dropping connections)

    logind settings: they take effect at the next reboot. Nothing to run.

  *** DO NOT run `systemctl restart systemd-logind` ***
  Restarting logind tears down the running desktop session: the screen goes
  black and the machine looks hung. There is no need for it - a reboot at any
  convenient time picks the settings up.

  To undo:
    sudo systemctl unmask sleep.target suspend.target hibernate.target hybrid-sleep.target
    sudo rm /etc/systemd/logind.conf.d/99-portal-login.conf
    sudo rm /etc/NetworkManager/conf.d/99-portal-login-powersave.conf

UNDO
}

do_status() {
  local c
  printf '\n== portal-login %s ==\n\n' "$VERSION"
  printf 'config : %s%s\n' "$CONF_FILE" "$([ -f "$CONF_FILE" ] && echo '' || echo '   (MISSING)')"
  printf 'portal : %s\n' "$PORTAL_URL"
  printf 'user   : %s\n' "${PORTAL_USERNAME:-<not set>}"
  printf 'passwd : %s\n' "$([ -n "$PORTAL_PASSWORD" ] && echo '<set>' || echo '<NOT SET>')"
  load_state
  if [ "${LAST_OK:-0}" -gt 0 ] 2>/dev/null; then
    printf 'last ok: %s (%sm ago)\n' "$(date -d "@$LAST_OK" 2>/dev/null || date -r "$LAST_OK" 2>/dev/null || echo "$LAST_OK")" \
           "$(( ($(date +%s) - LAST_OK) / 60 ))"
  fi
  printf 'fails  : %s\n\n' "${FAILS:-0}"
  c=$(classify); printf 'now    : %s (%s)\n\n' "${c%%|*}" "${c#*|}"
  if [ "$IS_MAC" = yes ]; then
    status_launchd
  elif have systemctl; then
    local _svc _tmr
    _svc=$(systemctl is-enabled "$APP.service" 2>/dev/null | head -1)
    _tmr=$(systemctl is-enabled "$APP.timer"   2>/dev/null | head -1)
    if [ "$_svc" = enabled ]; then
      printf 'mode   : always-on daemon (%s)\n\n' "$(systemctl is-active "$APP.service" 2>/dev/null | head -1)"
      systemctl status "$APP.service" --no-pager -n 0 2>/dev/null | head -5
      printf '\n'
    elif [ "$_tmr" = enabled ]; then
      printf 'mode   : systemd timer\n\n'
    else
      printf 'mode   : NOT INSTALLED - run: sudo %s install\n\n' "$APP"
    fi
    systemctl list-timers "$APP.timer" --no-pager 2>/dev/null | head -4
    printf '\n'
    journalctl -u "$APP" -n 20 --no-pager 2>/dev/null || true
  fi
  printf '\n'
}

# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
usage() {
  sed -n '3,32p' "$SELF" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

main() {
  local cmd="" ASSUME_YES=no verbose=no url_override="" conf_override=""
  INSTALL_MODE=timer
  while [ $# -gt 0 ]; do
    case "$1" in
      check|once|login|daemon|inspect|install|uninstall|harden|status) cmd=$1 ;;
      -c|--config)  conf_override=${2:?--config needs a path}; shift ;;
      -u|--url)     url_override=${2:?--url needs a URL}; shift ;;
      -v|--verbose) verbose=yes ;;
      --daemon)     INSTALL_MODE=daemon ;;
      --timer)      INSTALL_MODE=timer ;;
      -y|--yes)     ASSUME_YES=yes ;;
      -h|--help)    usage 0 ;;
      -V|--version) echo "$APP $VERSION"; exit 0 ;;
      *) printf 'unknown argument: %s\n\n' "$1" >&2; usage 2 ;;
    esac
    shift
  done
  cmd=${cmd:-once}
  [ -n "$conf_override" ] && CONF_FILE=$conf_override

  load_config
  [ -n "$url_override" ] && PORTAL_URL=$url_override
  [ "$verbose" = yes ] && LOG_LEVEL=debug
  export ASSUME_YES
  setup_runtime

  case "$cmd" in
    install)   do_install; return $? ;;
    uninstall) do_uninstall; return $? ;;
    harden)    do_harden; return $? ;;
    status)    do_status; return $? ;;
    inspect)   do_inspect; return $? ;;
    check)
      local c; c=$(classify)
      printf '%s: %s\n' "${c%%|*}" "${c#*|}"
      [ "${c%%|*}" = ONLINE ] && return 0 || return 1 ;;
  esac

  # once / login / daemon must never overlap with themselves
  if ! acquire_lock; then
    info "another $APP instance is already running - exiting"
    return 0
  fi

  case "$cmd" in
    once)   run_once ;;
    login)  run_once force ;;
    daemon) run_daemon ;;
  esac
}

# Set PORTAL_LOGIN_NO_MAIN=1 to source this file for tests without running it.
[ "${PORTAL_LOGIN_NO_MAIN:-}" = 1 ] || main "$@"
