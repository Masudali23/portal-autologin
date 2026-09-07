#Requires -Version 5.1
<#
.SYNOPSIS
  portal-login for Windows - unattended captive-portal re-authentication.

.DESCRIPTION
  Windows port of portal-login.sh. Keeps a machine logged in to a FortiGate-
  style captive portal (http://<gateway>:1000/) so it stays reachable when the
  session expires overnight. Runs as SYSTEM from Task Scheduler, so it works
  with nobody logged in and survives reboots.

  It drives the SAME curl invocations as the Linux/macOS script, using the
  curl.exe that ships with Windows 10 (1803+) and Windows 11. No browser,
  no extra modules.

.EXAMPLE
  Commands (run from an elevated PowerShell):
  .\portal-login.ps1 install      copy to C:\ProgramData\portal-login, register the scheduled task
  .\portal-login.ps1 inspect      show the portal's real login form
  .\portal-login.ps1 login -Trace force one login, verbose
  .\portal-login.ps1 status       task state, last result, recent log
  .\portal-login.ps1 check        report ONLINE / NEED_LOGIN / NETWORK_DOWN, never logs in
  .\portal-login.ps1 once         check, and log in only if needed  (what the task runs)
  .\portal-login.ps1 harden       never sleep on AC power, no NIC power saving
  .\portal-login.ps1 uninstall    remove the task and program files (keeps config)

  Credentials go in  C:\ProgramData\portal-login\portal-login.conf  (ACL: SYSTEM + Administrators only).

.NOTES
  Exit codes: 0 online / login ok, 1 login failed, 2 network down, 3 backing off, 4 misconfigured.
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [ValidateSet('check', 'once', 'login', 'inspect', 'install', 'uninstall', 'status', 'harden', 'help')]
  [string]$Command = 'once',
  [switch]$Trace,          # verbose logging (-Verbose is reserved by PowerShell)
  [switch]$Yes,            # assume yes for harden
  [string]$Config          # alternate config path
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$script:VERSION = '2.4.0'
$script:APP     = 'portal-login'

# ----------------------------------------------------------------------------
# defaults - every one of these can be overridden in the config file
# ----------------------------------------------------------------------------
$script:Cfg = [ordered]@{
  PORTAL_URL           = 'http://192.168.252.1:1000/'
  PORTAL_USERNAME      = ''
  PORTAL_PASSWORD      = ''
  LOGIN_URL            = ''
  USER_FIELD           = ''
  PASS_FIELD           = ''
  EXTRA_FIELDS         = ''
  INTERFACE            = 'auto'     # auto = physical NIC's IPv4; an IP pins it; any = no pin
  FORCE_IPV4           = 'yes'
  LOGOUT_BEFORE_LOGIN  = 'yes'
  KEEPALIVE_ENABLED    = 'yes'
  KEEPALIVE_URL        = ''
  HEARTBEAT_URL        = ''
  CONNECT_TIMEOUT      = 5
  MAX_TIME             = 15
  VERIFY_ATTEMPTS      = 6
  VERIFY_DELAY         = 3
  BACKOFF_BASE         = 300
  BACKOFF_MAX          = 3600
  ALERT_AFTER_FAILURES = 3
  ALERT_COMMAND        = ''
  LOG_LEVEL            = 'info'
  TRUST_PORTAL_ONLY    = 'no'
  UA                   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
}
$script:Probes = @(
  @{ url = 'http://connectivitycheck.gstatic.com/generate_204';    code = '204'; body = '' },
  @{ url = 'http://www.msftconnecttest.com/connecttest.txt';       code = '200'; body = 'Microsoft Connect Test' },
  @{ url = 'http://detectportal.firefox.com/success.txt';          code = '200'; body = 'success' },
  @{ url = 'http://captive.apple.com/hotspot-detect.html';         code = '200'; body = 'Success' }
)

# ----------------------------------------------------------------------------
# paths
# ----------------------------------------------------------------------------
$script:Base      = Join-Path $env:ProgramData $APP
$script:ConfFile  = if ($Config) { $Config } else { Join-Path $Base "$APP.conf" }
$script:StateFile = Join-Path $Base 'state.json'
$script:LogFile   = Join-Path $Base "$APP.log"
$script:CookieJar = Join-Path $Base 'cookies.txt'
$script:BinPath   = Join-Path $Base "$APP.ps1"
$script:TaskName  = $APP
$script:Curl      = Join-Path $env:SystemRoot 'System32\curl.exe'
$script:Tmp       = $null
$script:PhysIp    = $null
$script:TunnelDefault = $false
$script:NoPin     = $false

# ----------------------------------------------------------------------------
# logging  (never prints the password)
# ----------------------------------------------------------------------------
function LvlNum([string]$l) { switch ($l.ToLower()) { 'debug' {10} 'info' {20} 'warn' {30} 'warning' {30} 'error' {40} default {20} } }
function Redact([string]$s) {
  if ($Cfg.PORTAL_PASSWORD -and $s) { return $s.Replace($Cfg.PORTAL_PASSWORD, '********') }
  return $s
}
function Log([string]$level, [string]$msg) {
  if ((LvlNum $level) -lt (LvlNum $Cfg.LOG_LEVEL)) { return }
  $line = '{0} {1,-5} {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $level.ToUpper(), (Redact $msg)
  [Console]::Error.WriteLine($line)
  try {
    if (Test-Path $LogFile) {
      if ((Get-Item $LogFile).Length -gt 1MB) {           # simple size-based rotation
        Move-Item -Force $LogFile ($LogFile + '.1')
      }
    }
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
  } catch { }
}
function Dbg([string]$m)  { Log 'debug' $m }
function Info([string]$m) { Log 'info'  $m }
function Warn([string]$m) { Log 'warn'  $m }
function Err([string]$m)  { Log 'error' $m }
function Die([string]$m)  { Err $m; exit 4 }
function IsYes([string]$v)  { return ($v -and $v.ToString().ToLower() -in @('yes', 'true', '1', 'on')) }

# ----------------------------------------------------------------------------
# config  (KEY = VALUE, parsed - never executed - so any password is safe)
# ----------------------------------------------------------------------------
function Load-Config {
  if (-not (Test-Path $ConfFile)) { Dbg "no config file at $ConfFile"; return }
  $probes = @()
  foreach ($raw in (Get-Content -Path $ConfFile -Encoding UTF8)) {
    $line = $raw.TrimEnd("`r")
    if ($line -match '^\s*$' -or $line -match '^\s*[#;\[]') { continue }
    if ($line -notmatch '=') { continue }
    $i = $line.IndexOf('=')
    $key = $line.Substring(0, $i).Trim().ToUpper()
    $val = $line.Substring($i + 1)
    if ($val.StartsWith(' ')) { $val = $val.Substring(1) }
    if ($val.Length -ge 2 -and (($val[0] -eq '"' -and $val[-1] -eq '"') -or ($val[0] -eq "'" -and $val[-1] -eq "'"))) {
      $val = $val.Substring(1, $val.Length - 2)
    }
    if ($key -eq 'PROBE') {
      $parts = $val -split '\|', 3
      if ($parts.Count -ge 2) { $probes += @{ url = $parts[0]; code = $parts[1]; body = $(if ($parts.Count -ge 3) { $parts[2] } else { '' }) } }
      continue
    }
    if ($Cfg.Contains($key)) { $Cfg[$key] = $val } else { Dbg "ignoring unknown config key: $key" }
  }
  if ($probes.Count -gt 0) { $script:Probes = $probes }
  foreach ($k in 'CONNECT_TIMEOUT','MAX_TIME','VERIFY_ATTEMPTS','VERIFY_DELAY','BACKOFF_BASE','BACKOFF_MAX','ALERT_AFTER_FAILURES') {
    $Cfg[$k] = [int]$Cfg[$k]
  }
}

function Setup-Runtime {
  New-Item -ItemType Directory -Force -Path $Base | Out-Null
  $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("$APP-" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $Tmp | Out-Null
  if (-not (Test-Path $Curl)) { Die "curl.exe not found at $Curl - it ships with Windows 10 1803+ and Windows 11" }
}
function Cleanup { if ($Tmp -and (Test-Path $Tmp)) { Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue } }

# ----------------------------------------------------------------------------
# which NIC do we mean?  (same reasoning as the bash version: IPv6 or a tunnel
# can make the probe say "online" while the campus session is dead)
# ----------------------------------------------------------------------------
function Get-PhysIp {
  if ($script:PhysIp) { return $script:PhysIp }
  try {
    $bad = 'Tailscale|WireGuard|Hyper-V|vEthernet|VirtualBox|VMware|TAP-|OpenVPN|Bluetooth|Loopback|WSL|ZeroTier|Npcap'
    $routes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction Stop |
              Sort-Object RouteMetric, InterfaceMetric
    foreach ($r in $routes) {
      $ad = Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue
      if (-not $ad) { continue }
      if ($ad.InterfaceDescription -match $bad -or $ad.Name -match $bad) {
        $script:TunnelDefault = $true
        Warn "default route via '$($ad.Name)' (a tunnel/virtual adapter) - looking for a physical NIC"; continue
      }
      $ip = Get-NetIPAddress -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
      if ($ip) { $script:PhysIp = $ip.IPAddress; Dbg "pinning requests to $($ad.Name) ($($ip.IPAddress))"; return $script:PhysIp }
    }
  } catch { Dbg "interface detection failed: $($_.Exception.Message)" }
  return $null
}

function Curl-Args {
  $a = @('--silent', '--show-error',
         '--connect-timeout', $Cfg.CONNECT_TIMEOUT, '--max-time', $Cfg.MAX_TIME,
         '--insecure', '--noproxy', '*',
         '--user-agent', $Cfg.UA,
         '--header', 'Cache-Control: no-cache, no-store', '--header', 'Pragma: no-cache')
  if (IsYes $Cfg.FORCE_IPV4) { $a += '--ipv4' }
  if ($script:NoPin) { return $a }                 # a deliberately unpinned probe
  switch ($Cfg.INTERFACE.ToLower()) {
    { $_ -in '', 'any', 'none' } { }
    'auto' { $ip = Get-PhysIp; if ($ip) { $a += @('--interface', $ip) } }
    default { $a += @('--interface', $Cfg.INTERFACE) }
  }
  return $a
}

# Http-Get -Url u -Out file [-Follow]  ->  @{ code; effective; redirect } or $null if curl could not complete
function Http-Get([string]$Url, [string]$Out, [switch]$Follow) {
  $a = Curl-Args
  if ($Follow) { $a += @('--location', '--max-redirs', '10') }
  # Do NOT use PowerShell's `2>$err` here. In Windows PowerShell 5.1 redirecting a
  # native command's stderr wraps every line in a NativeCommandError, and under
  # $ErrorActionPreference='Stop' the first one TERMINATES the script - so one
  # timed-out probe would kill the run instead of yielding NETWORK_DOWN. Let curl
  # write its own stderr file; PowerShell then never sees it.
  $err = Join-Path $Tmp 'curl.err'
  $a += @('--stderr', $err, '-o', $Out, '-w', '%{http_code}|%{url_effective}|%{redirect_url}', $Url)
  $res = & $Curl @a
  if ($LASTEXITCODE -ne 0) {
    # [string] because -Raw on an empty file returns $null, and $null.Length
    # throws under Set-StrictMode -Version 2.
    $e = [string](Get-Content $err -Raw -ErrorAction SilentlyContinue)
    $e = ($e -replace '\s+', ' ').Trim()
    if ($e.Length -gt 200) { $e = $e.Substring(0, 200) }
    Dbg "curl $Url failed (rc=$LASTEXITCODE): $e"
    return $null
  }
  $p = ("$res" -split '\|', 3)
  return @{ code = $p[0]; effective = $(if ($p.Count -gt 1) { $p[1] } else { $Url }); redirect = $(if ($p.Count -gt 2) { $p[2] } else { '' }) }
}

# ----------------------------------------------------------------------------
# connectivity probes  (status AND body are checked; redirects are NOT followed)
# 0 = online, 1 = intercepted, 2 = no answer
# ----------------------------------------------------------------------------
function Probe-One($p) {
  $body = Join-Path $Tmp 'probe.body'
  $r = Http-Get -Url $p.url -Out $body
  if (-not $r) { return 2 }
  if ($r.code -eq $p.code) {
    if (-not $p.body) {
      if (-not (Test-Path $body) -or (Get-Item $body).Length -eq 0) { Dbg "probe $($p.url) -> clean $($r.code)"; return 0 }
      Dbg "probe $($p.url) -> $($r.code) but body non-empty"; return 1
    }
    $txt = Get-Content $body -Raw -ErrorAction SilentlyContinue
    if ($txt -and $txt.IndexOf($p.body, [StringComparison]::OrdinalIgnoreCase) -ge 0) { Dbg "probe $($p.url) -> clean $($r.code)"; return 0 }
  }
  Dbg "probe $($p.url) -> intercepted (code=$($r.code))"
  return 1
}
function Probe-Internet {
  $sawIntercept = $false
  foreach ($p in $Probes) {
    switch (Probe-One $p) { 0 { return 0 } 1 { $sawIntercept = $true } }
  }
  if ($sawIntercept) { return 1 }
  return 2
}

function Portal-HostPort([string]$u) { $u = $u -replace '^[a-z]+://', ''; return ($u -split '/', 2)[0] }
function Portal-Origin([string]$u)   { if ($u -match '^([a-z]+://[^/]+)') { return $Matches[1] }; return $u }
function Portal-Reachable {
  $hp = Portal-HostPort $Cfg.PORTAL_URL
  $h, $p = $hp -split ':', 2
  if (-not $p) { $p = 80 }
  try {
    $c = New-Object Net.Sockets.TcpClient
    $ar = $c.BeginConnect($h, [int]$p, $null, $null)
    $ok = $ar.AsyncWaitHandle.WaitOne(4000, $false)
    if ($ok) { $c.EndConnect($ar) }
    $c.Close()
    return $ok
  } catch { return $false }
}
function Portal-LooksLikeLogin {
  $u = if ($Cfg.LOGIN_URL) { $Cfg.LOGIN_URL } else { $Cfg.PORTAL_URL }
  $f = Join-Path $Tmp 'portal.html'
  $r = Http-Get -Url $u -Out $f -Follow
  if (-not $r) { return $false }
  $t = Get-Content $f -Raw -ErrorAction SilentlyContinue
  return ($t -match '(?i)type=["'']?password|name=["'']?(password|passwd|pwd)|<form')
}

# Windows' own verdict (NCSI) is a useful second opinion when nothing answered
function Ncsi-Verdict {
  try {
    $p = Get-NetConnectionProfile -ErrorAction Stop | Select-Object -First 1
    if ($p) { return "$($p.IPv4Connectivity)" }   # Internet | LocalNetwork | NoTraffic | Disconnected
  } catch { }
  return ''
}

# ----------------------------------------------------------------------------
# state classification  (identical logic to the bash version)
# ----------------------------------------------------------------------------
function Classify {
  if (IsYes $Cfg.TRUST_PORTAL_ONLY) {
    if ((Portal-Reachable) -and (Portal-LooksLikeLogin)) { return 'NEED_LOGIN|portal is serving a login form' }
    return 'ONLINE|portal is not serving a login form'
  }
  switch (Probe-Internet) {
    0 { return 'ONLINE|connectivity probe returned a clean response' }
    1 { return 'NEED_LOGIN|connectivity probe was intercepted by a portal' }
  }
  # A VPN kill-switch can drop the pinned-NIC probe while the box has internet
  # through the tunnel. That is not a captive portal - never log out for it.
  if ($script:TunnelDefault) {
    $script:NoPin = $true; $u = Probe-Internet; $script:NoPin = $false
    if ($u -eq 0) { return 'ONLINE|internet works through the VPN tunnel (pinned-NIC probe blocked) - nothing to do' }
  }
  $n = Ncsi-Verdict
  if ($n -eq 'Internet') { return 'ONLINE|Windows NCSI reports Internet (probes blocked?)' }
  if (Portal-Reachable) {
    if (Portal-LooksLikeLogin) { return 'NEED_LOGIN|no internet, and the portal is serving a login form' }
    return 'NEED_LOGIN|no internet, and the portal is answering'
  }
  $extra = if ($n) { " (NCSI: $n)" } else { '' }
  return "NETWORK_DOWN|no internet and the portal at $(Portal-HostPort $Cfg.PORTAL_URL) is not answering$extra"
}

# ----------------------------------------------------------------------------
# HTML form parsing  (regex; handles "quoted", 'quoted' and unquoted attributes)
# ----------------------------------------------------------------------------
function Get-Attr([string]$tag, [string]$name) {
  $m = [regex]::Match($tag, "(?i)\s$name\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s>/]+))")
  if (-not $m.Success) { return '' }
  foreach ($g in 1, 2, 3) { if ($m.Groups[$g].Success) { return $m.Groups[$g].Value } }
  return ''
}
function Html-Unescape([string]$s) { return [System.Net.WebUtility]::HtmlDecode($s) }

# the <form> that actually contains a password input, else the whole document
function Extract-LoginForm([string]$html) {
  foreach ($m in [regex]::Matches($html, '(?is)<form\b.*?</form>')) {
    if ($m.Value -match '(?i)<input[^>]*password') { return $m.Value }
  }
  Dbg 'no <form> with a password field; using the whole document'
  return $html
}
# -> array of @{name; value; type}
function Extract-Inputs([string]$frag) {
  $out = @()
  foreach ($m in [regex]::Matches($frag, '(?i)<input\b[^>]*>')) {
    $n = Get-Attr $m.Value 'name'; if (-not $n) { continue }
    $t = (Get-Attr $m.Value 'type').ToLower(); if (-not $t) { $t = 'text' }
    $out += @{ name = $n; value = (Get-Attr $m.Value 'value'); type = $t }
  }
  return $out
}
# First matching element's $key, or '' - never dots into an empty pipeline result.
function Pick($items, [scriptblock]$test, [string]$key) {
  foreach ($it in @($items)) { if (& $test $it) { return "$($it[$key])" } }
  return ''
}

function Form-Attr([string]$frag, [string]$attr) {
  $m = [regex]::Match($frag, '(?i)<form\b[^>]*>'); if ($m.Success) { return Get-Attr $m.Value $attr }; return ''
}
function Resolve-Url([string]$base, [string]$action) {
  if ($action -match '^https?://') { return $action }
  if (-not $action) { return $base }
  $origin = Portal-Origin $base
  if ($action.StartsWith('/')) { return $origin + $action }
  $path = $base.Substring($origin.Length); $path = ($path -split '[?#]', 2)[0]
  $path = $path.Substring(0, [Math]::Max(0, $path.LastIndexOf('/')))
  return "$origin$path/$action"
}

# ----------------------------------------------------------------------------
# find the real login URL: follow the interception (redirect OR window.location)
# - that is where a FortiGate hands out the per-session magic token
# ----------------------------------------------------------------------------
function Discover-LoginUrl {
  if ($Cfg.LOGIN_URL) { return $Cfg.LOGIN_URL }
  $body = Join-Path $Tmp 'intercept.body'
  foreach ($p in $Probes) {
    $r = Http-Get -Url $p.url -Out $body
    if (-not $r) { continue }
    if ($r.redirect -and $r.redirect -ne $p.url) { Dbg "interception redirect: $($r.redirect)"; return $r.redirect }
    $txt = Get-Content $body -Raw -ErrorAction SilentlyContinue
    if ($txt) {
      $m = [regex]::Match($txt, '(?i)(?:http-equiv=.refresh[^>]*url=|window\.location(?:\.href)?\s*=\s*.)(https?://[^"''>\s]+)')
      if ($m.Success) { Dbg "interception page points at: $($m.Groups[1].Value)"; return $m.Groups[1].Value }
    }
    break
  }
  Dbg 'no interception redirect found; using the configured portal URL'
  return $Cfg.PORTAL_URL
}

# ----------------------------------------------------------------------------
# state + backoff
# ----------------------------------------------------------------------------
$script:St = @{ FAILS = 0; NEXT_ATTEMPT = 0; LAST_OK = 0; LAST_STATE = ''; OFFLINE_SINCE = 0; KEEPALIVE_SAVED = '' }
function Now { return [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
function Load-State {
  if (-not (Test-Path $StateFile)) { return }
  try {
    $j = Get-Content $StateFile -Raw | ConvertFrom-Json
    foreach ($k in @($St.Keys)) { if ($j.PSObject.Properties[$k]) { $St[$k] = $j.$k } }
  } catch { }
}
function Save-State { try { $St | ConvertTo-Json | Set-Content -Path $StateFile -Encoding UTF8 } catch { } }
function Fire-Alert([string]$state, [string]$msg) {
  if (-not $Cfg.ALERT_COMMAND) { return }
  Info 'running ALERT_COMMAND'
  $env:PORTAL_STATE = $state; $env:PORTAL_MESSAGE = $msg; $env:PORTAL_HOST = $env:COMPUTERNAME
  try { & cmd.exe /c $Cfg.ALERT_COMMAND | Out-Null } catch { Warn 'ALERT_COMMAND failed' }
}

# ----------------------------------------------------------------------------
# the login itself
# ----------------------------------------------------------------------------
function Curl-CfgEscape([string]$s) { return $s.Replace('\', '\\').Replace('"', '\"') }
function Verify-Online {
  for ($i = 0; ; $i++) {
    if ((Probe-Internet) -eq 0) { return $true }
    if ($i + 1 -ge $Cfg.VERIFY_ATTEMPTS) { return $false }
    Start-Sleep -Seconds $Cfg.VERIFY_DELAY
  }
}

# returns 0 ok, 1 failed, 4 misconfigured, 5 credentials rejected, 6 portal served the login page again
function Login-Attempt([bool]$forced) {
  if (-not $Cfg.PORTAL_USERNAME) { Err "PORTAL_USERNAME is not set (edit $ConfFile)"; return 4 }
  if (-not $Cfg.PORTAL_PASSWORD) { Err "PORTAL_PASSWORD is not set (edit $ConfFile)"; return 4 }

  $pageUrl = Discover-LoginUrl

  # GUARD: never log out on a hunch - a transient probe failure must not tear
  # down a working session (that kills every live connection through it).
  if (-not $forced -and (Probe-Internet) -eq 0) {
    Info 'connectivity is fine on re-check - not logging out, nothing to do'; return 0
  }

  # Release the slot we hold BEFORE minting a token (a logout invalidates the
  # magic of the previous intercept). IIT BHU caps an account at 4 systems.
  if (IsYes $Cfg.LOGOUT_BEFORE_LOGIN) {
    $origin = Portal-Origin $pageUrl
    Load-State
    $tok = ''
    if ($St.KEEPALIVE_SAVED -and $St.KEEPALIVE_SAVED.Contains('?')) { $tok = ($St.KEEPALIVE_SAVED -split '\?', 2)[1] }
    if ($tok) { Info "releasing the session we hold: $origin/logout?<token>"; Http-Get -Url "$origin/logout?$tok" -Out (Join-Path $Tmp 'lo.html') | Out-Null }
    else      { Info "releasing any existing session: $origin/logout?";     Http-Get -Url "$origin/logout?"     -Out (Join-Path $Tmp 'lo.html') | Out-Null }
    $St.KEEPALIVE_SAVED = ''; Save-State
    Start-Sleep -Seconds 1
    $pageUrl = Discover-LoginUrl
  }

  Info "fetching login page: $pageUrl"
  $page = Join-Path $Tmp 'page.html'
  $r = Http-Get -Url $pageUrl -Out $page -Follow
  if (-not $r) { Err "cannot fetch the login page at $pageUrl"; return 1 }
  $eff = $r.effective
  $html = Get-Content $page -Raw -ErrorAction SilentlyContinue
  if (-not $html) { $html = '' }
  Dbg "login page: HTTP $($r.code), effective url $eff, $($html.Length) chars"

  $form   = Extract-LoginForm $html
  $inputs = @(Extract-Inputs $form)

  $passField = $Cfg.PASS_FIELD; $userField = $Cfg.USER_FIELD
  if (-not $passField) { $passField = Pick $inputs { param($x) $x.type -eq 'password' } 'name' }
  if (-not $passField) { $passField = Pick $inputs { param($x) $x.name -match '^(?i)(password|passwd|pwd|pass)$' } 'name' }
  if (-not $userField -and $passField) {
    $last = ''
    foreach ($i in $inputs) { if ($i.name -eq $passField) { $userField = $last; break }; if ($i.type -in 'text', 'email') { $last = $i.name } }
  }
  if (-not $userField) { $userField = Pick $inputs { param($x) $x.type -ne 'hidden' -and $x.name -match '(?i)user|login|uname|uid|email|account' } 'name' }

  $fgtMagic = ''
  if (-not $passField) {
    if ("$eff$pageUrl" -match '(?i)fgtauth|magic') {
      if ($eff -match '([0-9a-fA-F]{8,})$') { $fgtMagic = $Matches[1] }
      if (-not $fgtMagic) { $fgtMagic = Pick $inputs { param($x) $x.name -eq 'magic' } 'value' }
    }
    if ($fgtMagic) { Warn 'no password field parsed; falling back to the FortiGate field names'; $userField = 'username'; $passField = 'password' }
    elseif ((Probe-Internet) -eq 0) { Info 'no login form, but connectivity is fine - already authenticated'; return 0 }
    else {
      Err "could not find a password field on $eff - run 'inspect' and set USER_FIELD/PASS_FIELD in $ConfFile"
      Copy-Item $page (Join-Path $Base 'last-page.html') -Force -ErrorAction SilentlyContinue
      return 1
    }
  }
  Info "form fields: username=$(if ($userField) { $userField } else { '<none>' }) password=$passField"

  $action = Html-Unescape (Form-Attr $form 'action')
  $method = Form-Attr $form 'method'
  $target = Resolve-Url $eff $action
  Info "posting credentials to $target"

  # Everything goes through a curl config file - never argv, which any user on
  # the machine could read from the process list.
  $cfgPath = Join-Path $Tmp 'post.conf'
  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add('data-urlencode = "' + (Curl-CfgEscape "$userField=$($Cfg.PORTAL_USERNAME)") + '"')
  $lines.Add('data-urlencode = "' + (Curl-CfgEscape "$passField=$($Cfg.PORTAL_PASSWORD)") + '"')
  $seen = @{}
  foreach ($i in $inputs) {
    if ($i.name -in $userField, $passField) { continue }
    if ($seen.ContainsKey($i.name)) { Dbg "skipping repeated field $($i.name)"; continue }
    if ($i.type -in 'hidden', 'submit', 'button') {
      $v = Html-Unescape $i.value
      $lines.Add('data-urlencode = "' + (Curl-CfgEscape "$($i.name)=$v") + '"'); $seen[$i.name] = 1
      Dbg "carrying form field $($i.name)=$v"
    }
  }
  if ($fgtMagic -and -not $seen.ContainsKey('magic')) {
    $lines.Add('data-urlencode = "' + (Curl-CfgEscape "magic=$fgtMagic") + '"')
    $lines.Add('data-urlencode = "4Tredir=http://www.msftconnecttest.com/connecttest.txt"')
  }
  if ($Cfg.EXTRA_FIELDS) { foreach ($pair in ($Cfg.EXTRA_FIELDS -split '&')) { if ($pair) { $lines.Add('data-urlencode = "' + (Curl-CfgEscape $pair) + '"') } } }
  [IO.File]::WriteAllText($cfgPath, ($lines -join "`n") + "`n", (New-Object Text.UTF8Encoding $false))

  $result = Join-Path $Tmp 'result.html'
  $a = Curl-Args
  $a += @('--location', '--max-redirs', '10', '-K', $cfgPath, '-b', $CookieJar, '-c', $CookieJar, '--referer', $eff)
  if ($method -and $method.ToLower() -eq 'get') { $a += '--get' }
  $err = Join-Path $Tmp 'curl.err'
  $a += @('--stderr', $err, '-o', $result, '-w', '%{http_code}', $target)
  $code = & $Curl @a
  $rc = $LASTEXITCODE
  Remove-Item $cfgPath -Force -ErrorAction SilentlyContinue
  if ($rc -ne 0) { Err "login POST failed (curl rc=$rc): $(([string](Get-Content $err -Raw -ErrorAction SilentlyContinue)) -replace '\s+',' ')"; return 1 }
  $body = Get-Content $result -Raw -ErrorAction SilentlyContinue; if (-not $body) { $body = '' }
  Dbg "login POST -> HTTP $code, $($body.Length) chars"

  $low = $body.ToLower()
  if ($low -match 'firewall authentication failed|authentication failed|invalid username|invalid credentials|login failed|incorrect password|wrong password') {
    Err 'the portal rejected these credentials - check PORTAL_USERNAME / PORTAL_PASSWORD'
    Copy-Item $result (Join-Path $Base 'last-result.html') -Force -ErrorAction SilentlyContinue
    return 5
  }
  if ($low -match 'already logged in|concurrent|maximum number of|session limit') { Warn 'the portal says this account is already logged in elsewhere' }

  if (Verify-Online) {
    Info 'LOGIN OK - internet is reachable again'
    $m = [regex]::Match($body, '(?i)https?://[^"''\s>]*keepalive[^"''\s>]*')
    if ($m.Success) {
      $St.KEEPALIVE_SAVED = $m.Value; Info 'keepalive URL captured'
      $c = [regex]::Match($body, 'countDownTime[^0-9]*([0-9]+)')
      if ($c.Success) { Info "portal reports countDownTime=$($c.Groups[1].Value) (session is about $([int]$c.Groups[1].Value * 3 / 60) minutes)" }
    }
    return 0
  }
  if ($body -match '(?i)type=["'']?password|name=["'']?magic') {
    Warn 'the portal answered with its login page again rather than authenticating'
    Copy-Item $result (Join-Path $Base 'last-result.html') -Force -ErrorAction SilentlyContinue
    return 6
  }
  Err 'login was submitted but connectivity did not come back'
  Copy-Item $result (Join-Path $Base 'last-result.html') -Force -ErrorAction SilentlyContinue
  return 1
}

function Do-Login([bool]$forced) {
  $rc = Login-Attempt $forced
  if ($rc -eq 6) { Warn 'retrying once with a freshly minted token'; Start-Sleep 2; $rc = Login-Attempt $forced }
  if ($rc -eq 6) {
    Err 'the portal keeps returning its login page. In order of likelihood:'
    Err "  1. wrong username or password  -> check $ConfFile"
    Err '  2. the account is at its 4-system concurrent limit'
    Err "  3. the form wants a field we are not sending -> run 'inspect'"
    Err "  the portal's own reply is saved at $(Join-Path $Base 'last-result.html')"
    $rc = 1
  }
  return $rc
}

# ----------------------------------------------------------------------------
# one pass
# ----------------------------------------------------------------------------
function Run-Once([bool]$forced) {
  Load-State
  $now = Now
  if ($forced) { $state = 'NEED_LOGIN'; $reason = 'forced' }
  else { $c = Classify; $state, $reason = $c -split '\|', 2 }
  Info "state=$state ($reason)"

  switch ($state) {
    'ONLINE' {
      if ($St.FAILS -gt 0) { Info "clearing $($St.FAILS) recorded failure(s)" }
      $St.FAILS = 0; $St.NEXT_ATTEMPT = 0; $St.LAST_OK = $now; $St.LAST_STATE = 'ONLINE'; $St.OFFLINE_SINCE = 0
      Save-State
      $ka = if ($Cfg.KEEPALIVE_URL) { $Cfg.KEEPALIVE_URL } else { $St.KEEPALIVE_SAVED }
      if ($ka -and (IsYes $Cfg.KEEPALIVE_ENABLED)) { if (Http-Get -Url $ka -Out (Join-Path $Tmp 'ka.body')) { Dbg 'keepalive refreshed' } }
      if ($Cfg.HEARTBEAT_URL) { if (Http-Get -Url $Cfg.HEARTBEAT_URL -Out (Join-Path $Tmp 'hb.body') -Follow) { Dbg 'heartbeat sent' } }
      return 0
    }
    'NETWORK_DOWN' {
      $St.LAST_STATE = 'NETWORK_DOWN'; if (-not $St.OFFLINE_SINCE) { $St.OFFLINE_SINCE = $now }; Save-State
      Warn "the network itself looks down ($([int](($now - $St.OFFLINE_SINCE) / 60))m) - not attempting a login"
      return 2
    }
  }
  if (-not $forced -and $now -lt $St.NEXT_ATTEMPT) {
    Warn "backing off after $($St.FAILS) failure(s); next attempt in $($St.NEXT_ATTEMPT - $now)s"; return 3
  }
  $rc = Do-Login $forced
  switch ($rc) {
    0 { $St.FAILS = 0; $St.NEXT_ATTEMPT = 0; $St.LAST_OK = (Now); $St.LAST_STATE = 'ONLINE'; $St.OFFLINE_SINCE = 0; Save-State
        if (-not $forced) { Fire-Alert 'ONLINE' "re-authenticated $env:COMPUTERNAME" }; return 0 }
    4 { return 4 }
    5 { $St.FAILS++; $St.NEXT_ATTEMPT = (Now) + $Cfg.BACKOFF_MAX; $St.LAST_STATE = 'NEED_LOGIN'; Save-State
        Err "credentials rejected; not retrying for $($Cfg.BACKOFF_MAX)s"; Fire-Alert 'BAD_CREDENTIALS' "portal rejected the password on $env:COMPUTERNAME"; return 1 }
    default {
      $St.FAILS++
      $delay = $Cfg.BACKOFF_BASE; for ($i = 1; $i -lt $St.FAILS -and $delay -lt $Cfg.BACKOFF_MAX; $i++) { $delay *= 2 }
      if ($delay -gt $Cfg.BACKOFF_MAX) { $delay = $Cfg.BACKOFF_MAX }
      $St.NEXT_ATTEMPT = (Now) + $delay; $St.LAST_STATE = 'NEED_LOGIN'; Save-State
      Err "login failed ($($St.FAILS) in a row); next attempt in ${delay}s"
      if ($St.FAILS -eq $Cfg.ALERT_AFTER_FAILURES) { Fire-Alert 'LOGIN_FAILED' "$($St.FAILS) failed portal logins on $env:COMPUTERNAME" }
      return 1
    }
  }
}

# ----------------------------------------------------------------------------
# inspect
# ----------------------------------------------------------------------------
function Do-Inspect {
  $pageUrl = Discover-LoginUrl
  Write-Host ''; Write-Host "portal URL      : $($Cfg.PORTAL_URL)"; Write-Host "discovered URL  : $pageUrl"
  $page = Join-Path $Tmp 'page.html'
  $r = Http-Get -Url $pageUrl -Out $page -Follow
  if (-not $r) { Write-Host "`ncould not fetch that page. Are you on the campus network?`n"; return 1 }
  $html = Get-Content $page -Raw -ErrorAction SilentlyContinue; if (-not $html) { $html = '' }
  Write-Host "effective URL   : $($r.effective)"; Write-Host "HTTP status     : $($r.code)"; Write-Host "chars           : $($html.Length)`n"
  $form = Extract-LoginForm $html
  Write-Host "form action     : $(Form-Attr $form 'action')"; Write-Host "form method     : $(Form-Attr $form 'method')`n"
  $inputs = @(Extract-Inputs $form)
  Write-Host ('{0,-26} {1,-10} {2}' -f 'NAME', 'TYPE', 'VALUE'); Write-Host ('-' * 74)
  foreach ($i in $inputs) {
    $v = if ($i.type -eq 'password') { '***' } else { if ($i.value.Length -gt 40) { $i.value.Substring(0, 40) } else { $i.value } }
    Write-Host ('{0,-26} {1,-10} {2}' -f $i.name, $i.type, $v)
  }
  $pf = Pick $inputs { param($x) $x.type -eq 'password' } 'name'
  $uf = ''; $last = ''; foreach ($i in $inputs) { if ($i.name -eq $pf) { $uf = $last; break }; if ($i.type -in 'text', 'email') { $last = $i.name } }
  Write-Host "`nauto-detected   : USER_FIELD=$(if ($uf) { $uf } else { '<none>' })  PASS_FIELD=$(if ($pf) { $pf } else { '<none>' })"
  Write-Host "If those are wrong, pin them in $ConfFile`n"
  Copy-Item $page (Join-Path $Base 'last-page.html') -Force -ErrorAction SilentlyContinue
  Write-Host "raw page saved to $(Join-Path $Base 'last-page.html')`n"
  return 0
}

# ----------------------------------------------------------------------------
# install / uninstall / status / harden
# ----------------------------------------------------------------------------
function Need-Admin([string]$what) {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Die "'$what' needs an elevated PowerShell (run as Administrator)" }
}

function Write-ConfigTemplate([string]$path) {
  @"
# portal-login configuration (Windows).  Only SYSTEM and Administrators can read this file.
#
# Format is KEY = VALUE, one per line. The file is PARSED, never executed, so any
# character is safe in a password. Everything after the first '=' is taken
# literally to the end of the line. Comments must be on their own line.

# ---- credentials ---------------------------------------------------------
PORTAL_URL      = http://192.168.252.1:1000/
PORTAL_USERNAME =
PORTAL_PASSWORD =

# ---- form fields (leave blank to auto-detect; run 'inspect' to see them) --
USER_FIELD =
PASS_FIELD =
# LOGIN_URL    = http://192.168.252.1:1000/fgtauth
# EXTRA_FIELDS = realm=students&lang=en

# ---- behaviour -----------------------------------------------------------
# auto = pin every request to the physical NIC's IPv4 (skips Tailscale/WireGuard/
# Hyper-V adapters); an IP address pins it; any = no pinning.
INTERFACE  = auto
FORCE_IPV4 = yes

# Release the session slot before taking a new one. IIT BHU allows 4 systems
# per account and clearing an over-limit needs an in-person CCIS visit.
LOGOUT_BEFORE_LOGIN = yes
KEEPALIVE_ENABLED   = yes

# Dead-man's switch: pinged while healthy; silence is the alarm (healthchecks.io)
HEARTBEAT_URL =

BACKOFF_BASE = 300
BACKOFF_MAX  = 3600
CONNECT_TIMEOUT = 5
MAX_TIME        = 15
VERIFY_ATTEMPTS = 6
VERIFY_DELAY    = 3

# Runs on repeated failure (cmd.exe syntax). %PORTAL_MESSAGE% etc. are set.
ALERT_COMMAND        =
ALERT_AFTER_FAILURES = 3

# PROBE = http://connectivitycheck.gstatic.com/generate_204|204|
LOG_LEVEL = info
"@ | ForEach-Object { [IO.File]::WriteAllText($path, $_.Replace("`r`n", "`n"), (New-Object Text.UTF8Encoding $false)) }
}

function Lock-Down-Acl([string]$path) {
  # SYSTEM + Administrators only; strip inheritance so 'Users' cannot read it.
  # Well-known SIDs, not names ('Administrators' is 'Administratoren' on a German
  # Windows). On a directory, (OI)(CI) makes files created later inherit it.
  if (Test-Path $path -PathType Container) {
    & icacls.exe $path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
  } else {
    & icacls.exe $path /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
  }
}

function Do-Install {
  Need-Admin 'install'
  if (-not (Test-Path $Curl)) { Die "curl.exe not found - Windows 10 1803+ / Windows 11 required" }
  New-Item -ItemType Directory -Force -Path $Base | Out-Null
  Lock-Down-Acl $Base                                  # before ANY file lands in it
  if ((Resolve-Path $PSCommandPath).Path -ne $BinPath) { Copy-Item -Force $PSCommandPath $BinPath }
  if (-not (Test-Path $BinPath)) { Die "failed to install $BinPath" }
  Write-Host "  ok  installed $BinPath"

  if (Test-Path $ConfFile) { Write-Host "  ok  kept existing config $ConfFile" }
  else { Write-ConfigTemplate $ConfFile; Write-Host "  ok  created $ConfFile" }
  Lock-Down-Acl $ConfFile
  Write-Host "  ok  ACL: SYSTEM + Administrators only on $Base"

  # --- the scheduled task: the systemd timer + NetworkManager hook, in one ---
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$BinPath`" once"

  # every 5 minutes, indefinitely (no RepetitionDuration = repeat forever)
  $tEvery = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
  # 90 seconds after every boot
  $tBoot  = New-ScheduledTaskTrigger -AtStartup; $tBoot.Delay = 'PT90S'
  # the instant a network profile connects (event 10000) - the NM-hook equivalent
  $cls    = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace 'Root/Microsoft/Windows/TaskScheduler'
  $tNet   = New-CimInstance -CimClass $cls -ClientOnly
  $tNet.Subscription = '<QueryList><Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"><Select Path="Microsoft-Windows-NetworkProfile/Operational">*[System[EventID=10000]]</Select></Query></QueryList>'
  $tNet.Enabled = $true
  $tNet.Delay   = 'PT15S'

  $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
               -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($tEvery, $tBoot, $tNet) `
                         -Principal $principal -Settings $settings -Description 'Captive portal auto-login' | Out-Null
  Write-Host "  ok  scheduled task '$TaskName' registered (every 5 min, 90s after boot, and on network connect) as SYSTEM"
  Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

  Write-Host @"

running as: a scheduled task every 5 min (also 90s after boot, and on network connect)

next steps
  1. credentials:   notepad $ConfFile        (run notepad as Administrator)
  2. see the form:  .\portal-login.ps1 inspect
  3. test it:       .\portal-login.ps1 check
                    .\portal-login.ps1 login -Trace
  4. watch it:      .\portal-login.ps1 status
                    Get-Content $LogFile -Wait -Tail 20
  5. optional:      .\portal-login.ps1 harden

"@
}

function Do-Uninstall {
  Need-Admin 'uninstall'
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "  ok  scheduled task removed"
  Remove-Item -Force $BinPath -ErrorAction SilentlyContinue
  Write-Host "  ok  removed $BinPath"
  Write-Host "  !!  kept your config: $ConfFile"
  Write-Host "  !!  kept your logs:   $LogFile"
}

function Do-Status {
  Write-Host "`n== $APP $VERSION (Windows) ==`n"
  Write-Host "config : $ConfFile$(if (-not (Test-Path $ConfFile)) { '   (MISSING)' })"
  Write-Host "portal : $($Cfg.PORTAL_URL)"
  Write-Host "user   : $(if ($Cfg.PORTAL_USERNAME) { $Cfg.PORTAL_USERNAME } else { '<not set>' })"
  Write-Host "passwd : $(if ($Cfg.PORTAL_PASSWORD) { '<set>' } else { '<NOT SET>' })"
  Load-State
  if ($St.LAST_OK -gt 0) {
    $t = [DateTimeOffset]::FromUnixTimeSeconds([long]$St.LAST_OK).LocalDateTime
    Write-Host "last ok: $t ($([int](((Now) - $St.LAST_OK) / 60))m ago)"
  }
  Write-Host "fails  : $($St.FAILS)`n"
  $c = Classify; $s, $r = $c -split '\|', 2; Write-Host "now    : $s ($r)`n"
  $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if ($task) {
    $i = Get-ScheduledTaskInfo -TaskName $TaskName
    Write-Host "mode   : scheduled task ($($task.State))"
    Write-Host "         last run : $($i.LastRunTime)   result: $($i.LastTaskResult)"
    Write-Host "         next run : $($i.NextRunTime)`n"
  } else { Write-Host "mode   : NOT INSTALLED - run: .\portal-login.ps1 install`n" }
  if (Test-Path $LogFile) { Write-Host "-- last 20 log lines --"; Get-Content $LogFile -Tail 20 }
  Write-Host ''
}

function Do-Harden {
  Need-Admin 'harden'
  Write-Host @'

'harden' makes this PC survive an unattended night. It will:

  1. powercfg: never sleep or hibernate while on AC power (monitor may still turn off)
  2. powercfg /hibernate off - this also disables Fast Startup. REQUIRED: with Fast
     Startup on, a "shutdown" is really a hibernate, the next power-on is a resume,
     and the at-boot task trigger never fires.
  3. disable power management on every physical network adapter
     -> "allow the computer to turn off this device to save power" is a classic
        cause of "it was fine and then it just dropped at 2am"

These persist across reboots. Undo notes are printed at the end.

'@
  if (-not $Yes) {
    $a = Read-Host 'proceed? [y/N]'
    if ($a -notmatch '^(y|yes)$') { Write-Host 'aborted.'; return }
  }
  & powercfg.exe /change standby-timeout-ac 0   | Out-Null
  & powercfg.exe /change hibernate-timeout-ac 0 | Out-Null
  Write-Host '  ok  no sleep / hibernate on AC power'
  & powercfg.exe /hibernate off | Out-Null
  Write-Host '  ok  hibernate + Fast Startup off (so a real boot happens, and the boot trigger fires)'
  try {
    Get-NetAdapter -Physical | ForEach-Object {
      Disable-NetAdapterPowerManagement -Name $_.Name -ErrorAction SilentlyContinue
      Write-Host "  ok  power management off: $($_.Name)"
    }
  } catch { Warn "could not change adapter power management: $($_.Exception.Message)" }
  Write-Host @'

  To undo:
    powercfg /change standby-timeout-ac 30 ; powercfg /change hibernate-timeout-ac 180 ; powercfg /hibernate on
    Get-NetAdapter -Physical | Enable-NetAdapterPowerManagement

'@
}

# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
try {
  if ($Command -eq 'help') { Get-Help $PSCommandPath -Detailed; exit 0 }
  Load-Config
  if ($Trace) { $Cfg.LOG_LEVEL = 'debug' }
  Setup-Runtime
  $rc = 0
  switch ($Command) {
    'install'   { Do-Install }
    'uninstall' { Do-Uninstall }
    'harden'    { Do-Harden }
    'status'    { Do-Status }
    'inspect'   { $rc = Do-Inspect }
    'check'     { $c = Classify; $s, $r = $c -split '\|', 2; Write-Host "${s}: $r"; $rc = $(if ($s -eq 'ONLINE') { 0 } else { 1 }) }
    'once'      { $rc = Run-Once $false }
    'login'     { $rc = Run-Once $true }
  }
  exit $rc
} finally {
  Cleanup
}
