#!/usr/bin/env bash
#
# portal-check.sh - read-only health report for the GPU box.
#
#   Changes NOTHING. Runs no logins. Writes one report you can paste back.
#   Every secret is redacted: passwords are never printed, the campus username
#   is shown only as a length, session tokens and MACs are masked.
#
#   Usage:   ./portal-check.sh              (run it plain first)
#            sudo ./portal-check.sh         (fuller: reads root-only NM files)
#
#   The report is printed AND saved to ./portal-check-report.txt
#
set -uo pipefail

OUT="${1:-portal-check-report.txt}"
: > "$OUT"
say() { printf '%s\n' "$*" | tee -a "$OUT"; }
sec() { say ""; say "=================================================================="; say "$*"; say "=================================================================="; }
kv()  { printf '  %-34s %s\n' "$1" "$2" | tee -a "$OUT"; }
note(){ printf '  -> %s\n' "$*" | tee -a "$OUT"; }
have(){ command -v "$1" >/dev/null 2>&1; }

# --- redaction helpers ----------------------------------------------------
mask_hex() { sed -E 's/[0-9a-fA-F]{12,}/<token-redacted>/g'; }
mask_mac() { sed -E 's/([0-9a-fA-F]{2}:[0-9a-fA-F]{2}):[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}/\1:xx:xx:xx:xx/g'; }
scrub()    { mask_mac | mask_hex; }

IS_ROOT=no; [ "$(id -u)" -eq 0 ] && IS_ROOT=yes

say "portal-check report"
say "generated: $(date '+%Y-%m-%d %H:%M:%S %Z')"
say "running as: $(id -un)  (root: $IS_ROOT)"

# ==========================================================================
sec "1. SYSTEM"
kv "hostname"      "$(uname -n 2>/dev/null)"
kv "kernel"        "$(uname -r 2>/dev/null)"
kv "distro"        "$( . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" )"
kv "bash version"  "${BASH_VERSION:-unknown}"
kv "has systemd"   "$([ -d /run/systemd/system ] && echo yes || echo NO)"
kv "uptime"        "$(uptime -p 2>/dev/null || uptime 2>/dev/null)"
kv "session type"  "${XDG_SESSION_TYPE:-<none - headless or no user session>}"

sec "2. REQUIRED TOOLS"
for t in curl awk sed grep tr flock ip nmcli systemctl journalctl timeout; do
  if have "$t"; then kv "$t" "$(command -v "$t")"; else kv "$t" "*** MISSING ***"; fi
done
have curl || note "curl is required. Install it: sudo apt install -y curl"

# ==========================================================================
sec "3. NETWORK INTERFACES AND ROUTING"
if have ip; then
  say "  -- links --"
  ip -br link show 2>/dev/null | scrub | sed 's/^/  /' | tee -a "$OUT"
  say ""
  say "  -- IPv4 addresses --"
  ip -4 -br addr show 2>/dev/null | sed 's/^/  /' | tee -a "$OUT"
  say ""
  say "  -- IPv4 default route --"
  ip -4 route show default 2>/dev/null | sed 's/^/  /' | tee -a "$OUT"
  say ""
  say "  -- IPv6 default route (empty is GOOD here) --"
  V6=$(ip -6 route show default 2>/dev/null)
  if [ -n "$V6" ]; then
    printf '%s\n' "$V6" | sed 's/^/  /' | tee -a "$OUT"
    note "IPv6 default route EXISTS. The FortiGate portal intercepts IPv4 only, so a"
    note "probe could get a real 204 over IPv6 while IPv4 is still captive."
    note "portal-login sets FORCE_IPV4=yes to defend against this. Keep it on."
  else
    kv "ipv6 default route" "none (good)"
  fi

  PHYS=$(ip -4 route show default 2>/dev/null | awk '{for(n=1;n<NF;n++) if($n=="dev"){print $(n+1);exit}}')
  kv "physical iface (default route)" "${PHYS:-<none>}"
  case "$PHYS" in
    tailscale*|docker*|virbr*|wg*|tun*|tap*|br-*|zt*)
      note "WARNING: the default route goes via a tunnel/bridge. portal-login's"
      note "INTERFACE=auto will skip it and find the real NIC, but confirm that." ;;
  esac
  TUN=$(ip -br link show 2>/dev/null | awk '{print $1}' | grep -E '^(tailscale|wg|zt|tun|tap)' | tr '\n' ' ')
  kv "tunnel interfaces present" "${TUN:-none}"
else
  note "iproute2 missing - cannot inspect routing"
fi

# ==========================================================================
sec "4. THE CAPTIVE PORTAL"
GW=$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')
kv "default gateway" "${GW:-<unknown>}"
CAND=""
[ -n "${GW:-}" ] && CAND="$GW"
for g in 192.168.252.1 192.168.249.1; do
  case " $CAND " in *" $g "*) ;; *) CAND="$CAND $g" ;; esac
done
kv "gateways to probe" "$CAND"

for g in $CAND; do
  [ -z "$g" ] && continue
  say ""
  say "  -- http://$g:1000/ --"
  code=$(curl -4 -s -o /tmp/.pc.$$ -w '%{http_code}' --connect-timeout 4 --max-time 8 \
             --noproxy '*' --insecure "http://$g:1000/" 2>/dev/null)
  rc=$?
  if [ $rc -ne 0 ]; then
    kv "  result" "no answer (curl rc=$rc)"
  else
    kv "  http status" "$code"
    kv "  bytes" "$(wc -c < /tmp/.pc.$$ 2>/dev/null)"
    kv "  looks like a login form" "$(grep -qiE 'type=.?password|name=.?password' /tmp/.pc.$$ && echo YES || echo no)"
    say "  -- input fields found (names/types only, no values) --"
    tr -d '\r' < /tmp/.pc.$$ | awk '{gsub(/</,"\n<");print}' | awk '
      function attr(s,a,  lo,rest,q,e){lo=tolower(s)
        if(match(lo,"[[:space:]]" a "[[:space:]]*=[[:space:]]*")==0)return ""
        rest=substr(s,RSTART+RLENGTH); q=substr(rest,1,1)
        if(q=="\"" ){e=index(substr(rest,2),"\"");return (e?substr(rest,2,e-1):"")}
        if(q=="\047"){e=index(substr(rest,2),"\047");return (e?substr(rest,2,e-1):"")}
        e=match(rest,"[[:space:]>/]"); return (e?substr(rest,1,e-1):rest)}
      tolower($0)~/^<input/{n=attr($0,"name"); t=tolower(attr($0,"type"))
        if(n!="") printf "    name=%-14s type=%s\n", n, (t==""?"text":t)}
      tolower($0)~/^<form/{printf "    FORM action=%s method=%s\n", attr($0,"action"), attr($0,"method")}
    ' | sort -u | tee -a "$OUT"
  fi
  rm -f /tmp/.pc.$$
done

say ""
say "  -- how the gateway intercepts (this decides how we grab the token) --"
for p in http://connectivitycheck.gstatic.com/generate_204 http://detectportal.firefox.com/success.txt; do
  r=$(curl -4 -s -o /tmp/.pc2.$$ -w '%{http_code}|%{redirect_url}' --connect-timeout 4 --max-time 8 \
          --noproxy '*' "$p" 2>/dev/null)
  code=${r%%|*}; redir=${r#*|}
  say "  probe: $p"
  kv "    http status" "${code:-<no answer>}"
  kv "    Location header" "$(printf '%s' "${redir:-<none>}" | mask_hex)"
  if [ -s /tmp/.pc2.$$ ]; then
    js=$(grep -oE '(window\.location[^;]*|http-equiv=.refresh[^>]*)' /tmp/.pc2.$$ 2>/dev/null | head -1 | mask_hex)
    kv "    JS/meta redirect in body" "${js:-<none>}"
    kv "    body first 60 chars" "$(head -c 60 /tmp/.pc2.$$ | tr -d '\n' | mask_hex)"
  fi
  rm -f /tmp/.pc2.$$
  say ""
done

# ==========================================================================
sec "5. 802.1X / NETWORKMANAGER  (the 'works until I log out' trap)"
if have nmcli; then
  say "  -- devices --"
  nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device status 2>/dev/null | sed 's/^/    /' | tee -a "$OUT"
  say ""
  say "  -- connection profiles --"
  nmcli -t -f NAME,TYPE,DEVICE connection show 2>/dev/null | sed 's/^/    /' | tee -a "$OUT"
  dupes=$(nmcli -t -f NAME connection show 2>/dev/null | sort | uniq -d | tr '\n' ' ')
  [ -n "$dupes" ] && note "duplicate profile names present (${dupes}) - harmless, but they are listed below by UUID"
  say ""
  # Address profiles by UUID, not name: names are not unique, and
  # `nmcli -g <field> connection show <name>` returns one line PER match, which
  # corrupts every value and raised a false password-flags alarm.
  nmcli -t -f UUID,NAME connection show 2>/dev/null | while IFS= read -r row; do
    [ -z "$row" ] && continue
    uuid=${row%%:*}; cn=${row#*:}
    [ -z "$uuid" ] && continue
    say "  -- profile: $cn --"
    for f in 802-1x.eap 802-1x.identity 802-1x.password-flags connection.permissions \
             connection.autoconnect connection.autoconnect-retries ipv6.method; do
      v=$(nmcli -g "$f" connection show "$uuid" 2>/dev/null | head -1)
      case "$f" in
        802-1x.identity) [ -n "$v" ] && v="<set, ${#v} chars>" ;;
      esac
      kv "    $f" "${v:-<unset>}"
    done
    pf=$(nmcli -g 802-1x.password-flags connection show "$uuid" 2>/dev/null | head -1)
    eap=$(nmcli -g 802-1x.eap connection show "$uuid" 2>/dev/null | head -1)
    if [ -n "$eap" ] && [ "$pf" != "0" ] && [ -n "$pf" ]; then
      note "PROBLEM: this 802.1X profile has password-flags=$pf (not 0)."
      note "That means NetworkManager asks a logged-in desktop for the password."
      note "At 3am there is no desktop, so the box never associates at all."
      note "Fix: sudo nmcli connection modify $uuid 802-1x.password-flags 0 \\"
      note "       802-1x.password '<your-wifi-password>' connection.permissions \"\""
      note "     (UUID of \"$cn\" - use it, the names here are not unique)"
    fi
    say ""
  done
  kv "wifi powersave conf" "$(grep -rh 'powersave' /etc/NetworkManager/conf.d/ 2>/dev/null | tr '\n' ' ' || echo '<not set - default is ON, which can drop the link overnight>')"
else
  note "nmcli not present - is this box using systemd-networkd or ifupdown instead?"
fi

# ==========================================================================
sec "6. POWER / SLEEP  (can the box put itself to sleep at night?)"
if have systemctl; then
  for t in sleep.target suspend.target hibernate.target hybrid-sleep.target; do
    kv "$t" "$(systemctl is-enabled "$t" 2>/dev/null || echo unknown)"
  done
  note "'masked' is what you want. 'static'/'enabled' means the box CAN sleep."
fi
kv "logind IdleAction" "$(grep -rhs '^IdleAction' /etc/systemd/logind.conf /etc/systemd/logind.conf.d/ 2>/dev/null | tail -1 || echo '<default: ignore>')"
kv "logind HandleLidSwitch" "$(grep -rhs '^HandleLidSwitch' /etc/systemd/logind.conf /etc/systemd/logind.conf.d/ 2>/dev/null | tail -1 || echo '<default>')"

# ==========================================================================
sec "7. DISK ENCRYPTION AND UNATTENDED BOOT"
CRYPT=$(lsblk -o NAME,TYPE,FSTYPE 2>/dev/null | grep -i crypt | head -5)
if [ -n "$CRYPT" ]; then
  printf '%s\n' "$CRYPT" | sed 's/^/    /' | tee -a "$OUT"
  note "LUKS present. Do NOT enable REBOOT_AFTER_OFFLINE_MIN: the box would reboot"
  note "to a passphrase prompt and sit there until someone walks over."
else
  kv "LUKS encrypted root" "no (unattended reboot is safe)"
fi

# ==========================================================================
sec "8. REMOTE ACCESS"
for a in anydesk tailscale sshd ssh; do
  if have "$a"; then kv "$a binary" "$(command -v "$a")"; else kv "$a binary" "not installed"; fi
done
if have systemctl; then
  for u in anydesk sshd ssh tailscaled; do
    st=$(systemctl is-active "$u" 2>/dev/null)
    [ -n "$st" ] && [ "$st" != "inactive" ] && kv "service $u" "$st"
  done
fi
_n=$( (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep -c ':22 ' ); kv "sshd listening on :22" "${_n:-0}"
_n=$(pgrep -c anydesk 2>/dev/null | head -1);                                kv "anydesk processes"    "${_n:-0}"
if have tailscale; then
  _st=$(tailscale status 2>&1 | head -1)
  kv "tailscale status"  "${_st:-<unknown>}"
  kv "tailscale IPv4"    "$(tailscale ip -4 2>/dev/null | head -1 || echo '<none>')"
  _ssh=$(tailscale status --json 2>/dev/null | tr -d ' ' | grep -c '"RunningSSHServer":true')
  kv "tailscale SSH server" "$([ "${_ssh:-0}" -gt 0 ] && echo 'enabled' || echo 'NOT enabled')"
fi
if [ "${_n:-0}" -eq 0 ]; then
  _sshd=$( (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep -c ':22 ' )
  if [ "${_sshd:-0}" -eq 0 ]; then
    note "No AnyDesk, and nothing listening on :22. Your only way in is Tailscale."
    note "Confirm it works BEFORE you rely on it:  sudo tailscale up --ssh"
    note "then from your laptop:  ssh $(id -un)@$(uname -n)"
  fi
fi

# ==========================================================================
sec "9. PORTAL-LOGIN INSTALL STATE"
kv "binary installed" "$([ -x /usr/local/sbin/portal-login ] && echo yes || echo NO)"
kv "config present" "$([ -f /etc/portal-login/portal-login.conf ] && echo yes || echo NO)"
if [ -f /etc/portal-login/portal-login.conf ]; then
  kv "config permissions" "$(stat -c '%a %U:%G' /etc/portal-login/portal-login.conf 2>/dev/null)"
  if [ "$IS_ROOT" = yes ]; then
    u=$(grep -iE '^[[:space:]]*PORTAL_USERNAME' /etc/portal-login/portal-login.conf | head -1 | sed 's/.*=//' | tr -d ' ')
    p=$(grep -iE '^[[:space:]]*PORTAL_PASSWORD' /etc/portal-login/portal-login.conf | head -1 | sed 's/.*=//' | tr -d ' ')
    kv "PORTAL_USERNAME" "$([ -n "$u" ] && echo "<set, ${#u} chars>" || echo '*** EMPTY ***')"
    kv "PORTAL_PASSWORD" "$([ -n "$p" ] && echo "<set, ${#p} chars>" || echo '*** EMPTY ***')"
  else
    note "re-run with sudo to confirm the credentials are filled in"
  fi
fi
if have systemctl; then
  _v=$(systemctl is-enabled portal-login.timer 2>/dev/null | head -1); kv "timer enabled" "${_v:-not installed}"
  _v=$(systemctl is-active  portal-login.timer 2>/dev/null | head -1); kv "timer active"  "${_v:-not installed}"
  say ""
  systemctl list-timers portal-login.timer --no-pager 2>/dev/null | head -4 | sed 's/^/    /' | tee -a "$OUT"
  say ""
  say "  -- last 25 log lines --"
  journalctl -u portal-login -n 25 --no-pager 2>/dev/null | mask_hex | sed 's/^/    /' | tee -a "$OUT" \
    || note "no journal entries yet"
fi
[ -f /var/lib/portal-login/state ] && { say ""; say "  -- saved state --"; sed 's/^/    /' /var/lib/portal-login/state | mask_hex | tee -a "$OUT"; }
kv "NetworkManager hook" "$([ -x /etc/NetworkManager/dispatcher.d/90-portal-login ] && echo installed || echo NO)"

# ==========================================================================
sec "10. SUMMARY - what to look at"
say "  Paste this whole file back. The things that matter most:"
say "    * Section 4  - does the portal answer, and what are the real field names?"
say "    * Section 5  - is 802-1x.password-flags 0 ? (if not, nothing works at 3am)"
say "    * Section 6  - are the sleep targets masked?"
say "    * Section 3  - is there an IPv6 default route, or a tunnel interface?"
say "    * Section 7  - LUKS present? (decides whether a reboot watchdog is safe)"
say ""
say "  No passwords are in this file. Skim it before sharing anyway."
say ""
say "report saved to: $OUT"
