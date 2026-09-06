# portal-autologin

Unattended captive-portal re-authentication for a headless Linux box.

Built for the IIT (BHU) Varanasi network — a FortiGate portal on
`http://<gateway>:1000/` that drops your session after about 12 hours — but it
works with any FortiGate-style portal, and it discovers the gateway at runtime
rather than trusting a hardcoded IP.

Pure **bash + curl**. No browser, no Selenium, no chromedriver, no Python.
Runs as a root systemd service, so it works with nobody logged in.

---

## The problem this actually solves

The GPU training itself is fine — it keeps running overnight regardless. What
breaks is **access**: at some point in the night the portal session expires, the
box falls off the network, AnyDesk goes dead, and there is no way to look at the
run, adjust anything, or start the next job until somebody physically walks over
and logs in the next morning. Half a day of iteration time, lost, repeatedly.

This keeps the box authenticated so the machine is still *reachable* at 3am.

### Why not just re-POST the login every 10 minutes

Because on this network that can lock you out of your own account.

CCIS caps an account at **4 concurrent systems**, and clearing a
"Concurrent Over-limit" state requires **visiting CCIS in person with your ID
card** — there is no self-service reset. A dumb timer that re-POSTs credentials
can mint hundreds of sessions overnight and walk you straight into that state,
and you would discover it on a weekend.

So this tool:

- logs in **only** when connectivity is genuinely gone (not on a blind timer),
- GETs `/logout?` first to **release the slot it already holds**,
- in the healthy case refreshes the existing session through the portal's own
  `/keepalive` URL, which costs **no slot at all**,
- and after a *rejected* password it stops for a full hour instead of retrying,
  so a typo cannot burn attempts all night.

That keepalive behaviour is exactly what CCIS's own wired-setup PDF tells users
to do ("refrain from closing this dialog box").

---

## Files

| File | What it is | Copy to the box? |
|---|---|---|
| `portal-login.sh` | the tool — check, log in, install, harden | **yes** |
| `portal-check.sh` | read-only health report, changes nothing | **yes** |
| `README.md` | this guide | optional |
| `portal-autologin.py` + `.conf` + `.service` + `.timer` + `install.sh` | older Selenium/headless-Chrome fallback, only needed if your portal turns out to require JavaScript | no, unless needed |

**You only need two files: `portal-login.sh` and `portal-check.sh`.**

---

## Step 0 — get the files onto the GPU box

**Easiest — clone it on the box** (do this while it still has internet):

```bash
git clone https://github.com/Masudali23/portal-autologin.git && cd portal-autologin
```

```bash
chmod +x portal-login.sh portal-check.sh
```

**No git, or no internet on the box right now?** Copy the two files from your
laptop over SSH:

```bash
scp portal-login.sh portal-check.sh youruser@gpu-box:~/
```

or download them directly on the box:

```bash
curl -fsSLO https://raw.githubusercontent.com/Masudali23/portal-autologin/main/portal-login.sh -O https://raw.githubusercontent.com/Masudali23/portal-autologin/main/portal-check.sh && chmod +x portal-login.sh portal-check.sh
```

Failing all of that, AnyDesk's file transfer or a USB stick works fine — it is
two text files.

---

## Step 1 — run the health check BEFORE installing anything

This changes nothing, logs in to nothing, and prints no passwords. Run it plain
first, then with sudo for the fuller picture:

```bash
./portal-check.sh
```

```bash
sudo ./portal-check.sh
```

It writes `portal-check-report.txt`. Skim it, then paste it back — it answers the
questions that decide whether the rest will work:

- Does the portal answer, and what are its **real** form field names?
- Is `802-1x.password-flags` set to `0`? (if not, nothing works at 3am — see below)
- Are the sleep targets masked?
- Is there an IPv6 default route or a tunnel interface? (both can fake "online")
- Is the disk LUKS-encrypted? (decides whether a reboot watchdog is safe)

---

## Step 2 — install

```bash
sudo ./portal-login.sh install
```

That installs:

- `/usr/local/sbin/portal-login` — the binary
- `/etc/portal-login/portal-login.conf` — config, mode 600, root-only
- `/etc/systemd/system/portal-login.{service,timer}` — checks every 5 minutes, and 90s after every boot
- `/etc/NetworkManager/dispatcher.d/90-portal-login` — fires the check the instant a link comes up

---

## Step 2b — it keeps itself running; you never start it by hand

Do **not** run the script in a terminal and leave it there. It dies the moment
you close the window, log out, or the box reboots. `install` sets it up to run
by itself, as root, forever — starting again on its own after a reboot or a
power cut. Two ways, both survive reboots. Pick one:

**Mode A — timer (default).** A check every 5 minutes, plus 90 seconds after
every boot, plus instantly whenever a network link comes up.

```bash
sudo ./portal-login.sh install
```

**Mode B — always-on daemon.** One long-running process that loops forever.
`Restart=always` brings it back if it ever dies, and a systemd watchdog restarts
it if the loop wedges *without* exiting — the failure `Restart=always` alone
cannot catch.

```bash
sudo ./portal-login.sh install --daemon
```

Switching between them is safe: each mode disables the other, so you never end
up with both running.

There is no meaningful reliability difference. The timer is marginally more
robust because every check starts from a fresh process; the daemon is nicer if
you like seeing a live process and a continuously streaming log. Mode A is the
default for that reason.

### Prove it will come back on its own

```bash
systemctl is-enabled portal-login.timer portal-login.service 2>/dev/null
```

At least one must say `enabled` — that is what makes systemd start it at boot.
Then the honest test:

```bash
sudo reboot
```

and once it is back up:

```bash
sudo portal-login status
```

It should report a mode, and a `last ok` timestamp from the last few minutes,
with nobody having logged in or typed anything.

> **A power cut is not only a software problem.** Many desktop boards default
> "Restore on AC Power Loss" to *Power Off*, so after a cut the machine never
> turns on at all and no script can help. Check that setting in the BIOS while
> you are at the machine. Your disk is not LUKS-encrypted, so provided the BIOS
> powers on, the box boots unattended and re-authenticates by itself.

## Step 3 — where the username and password go

**In one file, on the box, that only root can read:**

```
/etc/portal-login/portal-login.conf
```

Open it:

```bash
sudo nano /etc/portal-login/portal-login.conf
```

Find these two lines near the top and fill them in — your campus internet login,
the same one you type into the browser popup:

```
PORTAL_USERNAME = your_campus_username
PORTAL_PASSWORD = your_campus_password
```

Save with **Ctrl-O**, Enter, then exit with **Ctrl-X**.

Then confirm the permissions are right:

```bash
sudo chmod 600 /etc/portal-login/portal-login.conf && sudo ls -l /etc/portal-login/portal-login.conf
```

You should see `-rw------- 1 root root`.

**Notes on the password:**

- The file is *parsed*, never executed, so `#`, `=`, `$`, spaces, quotes and
  backslashes in your password are all safe. Do not add quotes around it.
- Everything after the first `=` is taken literally to the end of the line.
- Never put your password on a command line — it would be visible to every user
  on the box via `ps`. This tool never does that either; it passes credentials to
  curl through a mode-600 config file.
- Don't paste your password into a chat, an issue, or this repo.

If you would rather not keep it in a file at all, systemd credentials work too:

```bash
sudo install -m 600 /dev/stdin /etc/portal-login/password
```

then add `LoadCredential=portal-password:/etc/portal-login/password` to the
service unit and leave `PORTAL_PASSWORD` blank.

---

## Step 4 — verify against the real portal

This is the step that actually proves it works, and it must be run **on the
campus network**.

```bash
sudo portal-login inspect
```

Prints the URL it discovered, the form action, and every input field with its
name and type. Check the auto-detected `USER_FIELD` / `PASS_FIELD` at the bottom.
If they are wrong, pin the correct names in the config — that bypasses
auto-detection entirely.

Now force one real login:

```bash
sudo portal-login login -v
```

You want to see `LOGIN OK - internet is reachable again`. It will also print
something like `countDownTime=14400`, which tells you your **real** session
length: `countDownTime × 3` seconds. 14400 × 3 = 43200s = exactly 12 hours.

Then:

```bash
sudo portal-login status
```

```bash
journalctl -u portal-login -f
```

Leave that last one running for 10 minutes and you should see the timer fire and
report `state=ONLINE`.

---

## Step 5 — stop the box killing itself overnight

```bash
sudo portal-login harden
```

Asks for confirmation, then masks suspend/hibernate, tells logind to ignore idle
and lid events, disables wifi power-saving, and sets NetworkManager to
auto-reconnect with infinite retries. It prints exact undo instructions at the end.

Wifi power-saving in particular is a very common cause of "it was fine and then it
just dropped at 2am" — the card sleeps and never cleanly wakes.

Apply it (this briefly drops the network, so do it while you're present):

```bash
sudo systemctl restart systemd-logind NetworkManager
```

### The 802.1X trap — check this even if you do nothing else

IIT BHU requires PEAP/MSCHAPv2 to associate, *before* the portal even appears.
If that profile was created from the desktop GUI, the password is probably
**agent-owned**: NetworkManager asks a logged-in desktop session for it, and at
3am there is no desktop session. The box then has no link at all, and no portal
script on earth can help.

```bash
nmcli -f 802-1x.identity,802-1x.password-flags,connection.permissions connection show "YOUR-PROFILE-NAME"
```

`password-flags` must be `0 (none)` and `connection.permissions` must be empty.
If it isn't:

```bash
sudo nmcli connection modify "YOUR-PROFILE-NAME" 802-1x.password-flags 0 connection.permissions "" connection.autoconnect yes connection.autoconnect-retries 0
```

```bash
sudo nmcli connection modify "YOUR-PROFILE-NAME" 802-1x.password '<your-wifi-password>'
```

Test it properly: **reboot, and check connectivity before logging in
graphically.** Logging out is not the same test.

---

## Step 6 — find out when it breaks, without being there

Alerting *on failure* cannot work here: a failure means there is no internet to
alert over. So invert it — ping while healthy and let **silence** be the alarm.

Make a free check at [healthchecks.io](https://healthchecks.io), copy its ping
URL, and put it in the config:

```bash
sudo nano /etc/portal-login/portal-login.conf
```

```
HEARTBEAT_URL = https://hc-ping.com/your-uuid-here
```

Set the grace period to about 15 minutes. If the box drops, you get an email or
push notification within 15 minutes instead of finding out in the morning.

---

## Step 7 — making the remote access itself more reliable

With Steps 2–5 done, the box stays online and awake, so AnyDesk has a working
network to reconnect over — which is the thing that was actually failing. That
may be all you need.

**But first, confirm you actually have a way in.** `portal-check.sh` section 8
tells you. If it reports no AnyDesk process, nothing listening on `:22`, and
Tailscale SSH not enabled, then keeping the box online does not help — there is
nothing to connect *to*. Enable one of them while you are physically at the
machine:

```bash
sudo tailscale up --ssh --hostname gpu-box
```

or install a normal SSH server:

```bash
sudo apt install -y openssh-server && sudo systemctl enable --now ssh
```

Verify from your laptop before you walk away.

If you want something sturdier, know this first:

> CCIS states there is **no institute VPN facility**, and CAIT clause 10
> prohibits setting up "unauthorized server(s) and client(s) of any kind
> (e.g. vpn, proxy, mail, web or hub etc.)". AnyDesk is arguably in the same
> category and you are already using it — but existing practice is not
> permission. **Ask your supervisor or CCIS before installing a tunnel.**

With permission, Tailscale is the better tool: a free mesh VPN that traverses
campus NAT, runs as a system service with nobody logged in, and reconnects on its
own the moment `portal-login` restores internet.

```bash
curl -fsSL https://tailscale.com/install.sh | sh
```

```bash
sudo tailscale up --ssh --hostname gpu-box
```

Then from any device on your tailnet:

```bash
ssh gpu-box
```

`--ssh` means no keys and no open ports. Do this **while physically at the
machine** and confirm access from your laptop before relying on it.

For a notebook, forward the port instead of using a remote desktop:

```bash
ssh -L 8888:localhost:8888 gpu-box
```

**Keep `INTERFACE = auto` in the config if you do this** — see below.

### Optional: make jobs survive a reboot too

Your training already survives a disconnect, because AnyDesk attaches to the
box's own desktop session and the process keeps running when you disconnect. It
does *not* survive a reboot or an accidental session logout. If you start using
SSH, run long jobs inside `tmux` so they are not children of the connection:

```bash
sudo apt install -y tmux
```

```bash
tmux new -s train
```

Start the job, detach with **Ctrl-b** then **d**, reattach later with
`tmux attach -t train`. For surviving reboots, checkpoint every epoch.

---

## Command reference

```bash
sudo portal-login check      # report state, never logs in
sudo portal-login once       # check, and log in only if needed (what the timer runs)
sudo portal-login login      # force a login attempt now
sudo portal-login inspect    # dump the portal's real login form
sudo portal-login status     # config + state + timer + recent log
sudo portal-login daemon     # loop forever instead of using the timer
sudo portal-login install    # install binary, config, systemd units, NM hook
sudo portal-login harden     # no suspend, no wifi powersave, autoreconnect
sudo portal-login uninstall  # remove it all (keeps your config and logs)
```

Flags: `-v` verbose, `-c FILE` alternate config, `-u URL` override portal URL,
`-y` assume yes, `-h` help, `-V` version.

Watching it:

```bash
journalctl -u portal-login -f
```

```bash
systemctl list-timers portal-login.timer
```

Exit codes: `0` online / login ok · `1` login failed · `2` network down ·
`3` backing off after failures · `4` misconfigured.

---

## How it decides what to do

| Situation | Verdict | Action |
|---|---|---|
| Probe returns a clean 204 / `success` | ONLINE | refresh keepalive only |
| Probe intercepted or redirected | NEED_LOGIN | logout, then log in |
| Nothing answers, gateway portal does | NEED_LOGIN | logout, then log in |
| Nothing answers and gateway is silent | NETWORK_DOWN | **do not** log in |

That last row matters. If wifi has genuinely dropped, a login attempt cannot
succeed — it is pure risk against your 4-session cap. A link outage must never
trip the auth circuit-breaker.

After a failed login it backs off 5min → 10 → 20 → up to an hour.

### Why `INTERFACE = auto` matters

Every request is pinned to the physical NIC and forced to IPv4. Not cosmetic —
it defends against two ways the check can silently lie to you:

- **IPv6** — the FortiGate intercepts IPv4/HTTP. If campus hands out routable
  IPv6, the probe gets a genuine 204 while all IPv4 is still captive, and the
  script would happily report "online" all night.
- **Tunnels** — if you install Tailscale (Step 7), an unpinned probe can start
  egressing through the tunnel and report "online" indefinitely after the campus
  session has died.

Leave it on `auto`.

---

## Troubleshooting

**`portal-login login` prints nothing at all** — fixed in v2.0.1. A lock bug
(`exec 9>file 2>/dev/null`, which redirects stderr *permanently* rather than just
for that command) silenced every log line whenever `flock` was present. `inspect`
and `status` still printed because they run before the lock is taken. If you see
this, `git pull` and reinstall.

**The gateway is different on wifi than on LAN** — that is normal here. IIT BHU
runs a FortiGate per zone: you may hit `192.168.252.1` on wifi and
`192.168.249.1` on the departmental LAN. `PORTAL_URL` in the config is only a
last-resort fallback; what actually matters is that the tool reads the gateway
out of the interception at runtime, so it follows you between wifi and LAN with
no config change. `sudo portal-login inspect` prints the one it found under
"discovered URL".

**"could not find a password field"** — run `sudo portal-login inspect` and set
`USER_FIELD` / `PASS_FIELD` explicitly in the config. The raw page is saved to
`/var/lib/portal-login/last-page.html`.

**Login submitted but connectivity never returns** — the portal's response is at
`/var/lib/portal-login/last-result.html`. Read it; it usually says why. The
classic FortiGate failure is a **stale `magic` token**, which looks like HTTP 200
plus the login page again, forever, with no error text. This tool defends against
it by taking `magic` from a single fresh intercept per attempt and never
following redirects while doing so.

**Nothing happens at 3am but it works when you're logged in** — that is the
802.1X trap in Step 5. Check `password-flags`.

**Your gateway is `192.168.252.1` but other IIT BHU scripts use
`192.168.249.1`** — different buildings sit behind different FortiGate gateways.
That is exactly why this discovers the portal URL from the interception at
runtime instead of trusting the configured one. Move the box, it still works.

**Campus blocks the probe hosts even when you're online** — add your own `PROBE`
lines to the config:

```
PROBE = http://something-you-know-works/|200|expected text
```

**The login page turns out to need JavaScript** — a small minority do. Use the
`portal-autologin.py` Selenium fallback in this repo. Heavier and more brittle;
only reach for it if `inspect` shows no usable form.

**Before enabling `REBOOT_AFTER_OFFLINE_MIN`** — check two things, or it does
more harm than good:

```bash
lsblk -o NAME,TYPE,FSTYPE | grep crypt
```

If the root is LUKS, the box reboots to a passphrase prompt and stays there.
Also check the BIOS "Restore on AC Power Loss" setting — it often defaults to
*Power Off*, so after a building power cut the machine never comes back at all.

---

## Testing

Development was done against a mock FortiGate portal (a small Python server that
intercepts, mints a per-session `magic`, and validates credentials), covering:
both interception styles (302-with-token and HTTP-200-with-`window.location`),
passwords containing `space & # = + % " ' \`, wrong-password backoff, refusing to
log in when the link is down, concurrent-run locking with stale-lock recovery,
and confirming the healthy path consumes no extra session slots.

---

## One honest caveat

The portal speaks plain HTTP on port 1000, so your campus password crosses the
departmental LAN unencrypted — with this tool, with your browser, with anything.
That is the portal's design, not this script's. Port 1003 (HTTPS) does not really
help, since the gateway's certificate will not validate and you would need `-k`
anyway. Use a password you do not reuse elsewhere, and note that you cannot
rotate it without an in-person CCIS visit.

---

## Licence

MIT
