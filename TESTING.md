# Drawbridge 2.0 release checklist

Run this checklist on a disposable Windows 10/11 `win-x64` VM from a clean
snapshot. Test with one administrator account and one standard child account.
Record the installer hash, Windows build, adapter type, and every observed
result in the release ticket.

## Automated gate

- [ ] `dotnet restore .\Drawbridge.sln` succeeds from a clean package cache.
- [ ] `dotnet build .\Drawbridge.sln -c Release --no-restore -p:TreatWarningsAsErrors=true`
      has no warnings or errors.
- [ ] `dotnet exec --roll-forward Major .\Drawbridge.Core.Tests\bin\Release\net8.0\Drawbridge.Core.Tests.dll`
      passes all harness cases, including the
      filter ladder, Adblock parsing, DNS NXDOMAIN construction, whitelist
      essentials, zero-domain cache guard, migration, lifetime counts, cleanup
      verification, SSRF defenses, transactional dual-stack listeners, restart
      intent, tray startup options, protected PIN writes, empty-DACL repair, and
      unsafe-link rejection.
- [ ] `build.ps1 -SkipInstaller` exits nonzero when any command fails and creates
      clean self-contained `win-x64` service/app publishes without stale files.
- [ ] Inno Setup 6.4 or newer compiles `drawbridge.iss` without warnings.

## Fresh install and service resilience

- [ ] Begin with no `%ProgramData%\Drawbridge` and no `DrawbridgeService`.
- [ ] Install as administrator and confirm the service display name is
      **Drawbridge Filtering Service**, startup is automatic, and the
      process runs in Session 0.
- [ ] Confirm the common Startup shortcut targets `Drawbridge.App.exe`, passes
      `--startup`, uses the install directory as its working directory, and is
      present after both a fresh install and an upgrade from 2.0.1.
- [ ] Confirm `%ProgramData%\Drawbridge` grants full control only to SYSTEM and
      Administrators and read/execute to Users. From the child account, attempts
      to modify `settings.json` or delete `pin.json` must fail.
- [ ] After setting a PIN, confirm the standard child cannot read `pin.json`,
      while the LocalSystem service can still verify it after a restart.
- [ ] On this genuinely empty data root, confirm service configuration defaults
      system DNS routing on and every active real adapter points to both loopbacks.
- [ ] Set the parent PIN before allowing the child account to sign in; record
      this first-install bootstrap step in deployment instructions.
- [ ] Reboot. Before any interactive login, query the machine remotely or inspect
      the service/event log and prove filtering started.
- [ ] Log in as a standard user. Confirm one non-elevated `Drawbridge.App.exe`
      process starts in that interactive session, the dashboard does not flash or
      appear on the taskbar, and the Drawbridge tray icon becomes available.
- [ ] Log in, log out, and log in as a different user; filtering must survive.
- [ ] Run `taskkill /F /IM Drawbridge.Service.exe` as administrator. Confirm SCM
      restarts it after approximately 5 seconds. Repeat and confirm the 15-second
      recovery action, then the 60-second action.
- [ ] Confirm operational messages appear in Windows Event Log and
      `%ProgramData%\Drawbridge\logs`.
- [ ] Stop the service normally with `sc stop DrawbridgeService`. Confirm adapter
      DNS is restored to automatic before the DNS listeners exit. Start it and
      confirm the saved desired routing is applied again.
- [ ] On a disposable 2.0.0 install, reproduce the protected-empty-DACL defect and
      its unversioned false routing preference, then upgrade. Confirm 2.0.2 repairs
      descendant ownership/ACLs, restores routing once, and remains exact on a
      second restart without exposing `pin.json` or an orphan `.pin.json.*.tmp`.
- [ ] Occupy one required loopback port, start the service, and exhaust all six
      bind attempts. Confirm partial sockets are disposed, automatic DNS is
      restored even from a partially routed state, the API reports degraded
      status, and maintenance retries eventually recover after releasing it.

## DNS correctness

- [ ] Wait for both default HaGeZi lists to update. Confirm domain count is
      non-zero and `use-application-dns.net` appears as a custom rule.
- [ ] `nslookup use-application-dns.net 127.0.0.1` returns NXDOMAIN.
- [ ] `nslookup example.com 127.0.0.1` returns a normal upstream response.
- [ ] `nslookup -vc example.com 127.0.0.1` succeeds, exercising DNS-over-TCP.
- [ ] Repeat IPv4 checks against `::1`.
- [ ] Generate an upstream ICMP port-unreachable condition and verify all UDP
      listeners continue answering subsequent queries.
- [ ] Exercise a truncated/large response and verify TCP retry does not stall.
- [ ] Add a more-specific allow rule below a blocked parent and confirm it wins;
      add a still-more-specific block and confirm the first specificity match wins.
- [ ] Serve a 200-OK HTML/error body for an existing list URL. Update and confirm
      the non-empty cache and active domain count are retained.
- [ ] Return 304 with matching ETag/Last-Modified and confirm no cache rewrite.
- [ ] Make both upstream list servers unreachable and confirm cached rules remain.
- [ ] Try to add HTTP, localhost, private-IP, private-DNS-answer, and redirect-to-
      private blocklist URLs. Every source must be rejected; a public HTTPS list
      with only public redirect/DNS targets must still update.
- [ ] Connect or enable a new real Ethernet/Wi-Fi adapter while routing is enabled.
      Confirm the service detects the bypass and routes it without a restart.

## UI and modes

- [ ] Run the app as the standard account. It must not request elevation.
- [ ] Launch with `--startup` and `--minimized` separately; both must initialize
      the tray and polling while keeping the dashboard hidden. A duplicate
      automatic launch must exit silently, while a duplicate manual launch may
      explain that Drawbridge is already running.
- [ ] With two users concurrently signed in, confirm each session has exactly one
      tray process and that signing out one session does not remove the other.
      While the second session remains active, confirm setup detects the global
      installer-presence marker and refuses to replace in-use files silently.
- [ ] Verify the branded window, taskbar, Start-menu, and desktop shortcut icons;
      the castle tray icon's green/red status badge and tooltip; sidebar
      navigation; 2-second status/log refresh; and the 14-day chart.
- [ ] Close the window; it hides to the tray and filtering continues. Exit from
      the tray; filtering still continues and a balloon explains that fact.
- [ ] Stop the service and verify the clear **Service not running** state. Use
      **Start Service**, approve the single UAC prompt, and confirm recovery.
- [ ] Launch the app while the service is unavailable and immediately choose tray
      **Exit** or close the window. Until one successful status response establishes
      PIN state, both paths must fail closed and offer to start the service.
- [ ] Enter whitelist mode through its strong confirmation dialog. Confirm an
      arbitrary unlisted domain is NXDOMAIN, an allowed domain resolves, and
      Windows essentials (including Microsoft update/connectivity names) resolve.
- [ ] Return to blocklist mode and confirm normal resolution resumes.
- [ ] Enable system DNS routing and confirm every active real Ethernet/Wi-Fi
      adapter uses `127.0.0.1` and `::1`; virtual/WFP/Wi-Fi Direct adapters must
      remain unchanged.
- [ ] In Firefox with secure DNS enabled, query the DoH canary and confirm Firefox
      falls back after `use-application-dns.net` is blocked.

## PIN and dashboard security

- [ ] As the parent, set a PIN immediately after install. Restart the app and
      confirm the lock overlay appears before any
      controls can be used and the window cannot close while locked.
- [ ] Submit wrong PINs and confirm the app delay escalates by 2 seconds per
      attempt to a 30-second cap.
- [ ] With `curl`, confirm mutations return 403 without
      `X-Drawbridge-Client: Drawbridge.App`, 415 for a non-JSON body, and 403
      whenever an `Origin` header is present. PIN verification follows these
      desktop-client/JSON rules too.
- [ ] With a PIN set, confirm every mutation except `/api/pin/verify` returns 401
      without a valid `X-Drawbridge-Pin`; read endpoints remain available without
      either header on localhost. Confirm concurrent wrong guesses remain globally
      serialized and each completed wrong verification incurs at least 1.5 seconds.
- [ ] Verify correct unlock, lock-now, change-PIN, remove-PIN, and locked Exit.
- [ ] Set a 13–128-character PIN through the API and migrate a legacy non-digit
      PIN; the app's unlock box must accept both even though its new-PIN UI offers
      a simpler 4–12-digit policy.
- [ ] Enable the web monitor. Confirm the **Drawbridge Monitor** inbound firewall
      rule exists and the UI shows usable LAN URLs.
- [ ] From a second LAN device, open port 8053, verify machine/uptime/mode/counts/
      recent blocks, log in with the PIN, and confirm wrong PINs impose 1.5 seconds.
- [ ] Disable the monitor and confirm both listener and firewall rule disappear.

## Cleanup, uninstall, and recovery

- [ ] Click **Undo all system changes**. Confirm adapter DNS is DHCP, DNS cache is
      flushed, the monitor firewall rule is gone, and legacy scheduled task
      `Drawbridge` is absent.
- [ ] Repeat cleanup when the firewall rule and legacy task are already absent;
      verified absence must be idempotent success. Force each delete/probe to fail
      in turn and confirm cleanup returns nonzero without clearing safety settings.
- [ ] Upgrade over a running prior build. Confirm setup waits for SERVICE_STOPPED
      before replacing files, checks every service policy command, preserves
      LocalSystem/automatic/recovery settings, starts the service, and verifies
      RUNNING. Cancel or inject a failure after the stop and confirm the retained
      service is restarted rather than leaving dead loopback DNS. On a failed
      fresh install, also confirm no newly-created common Startup shortcut remains.
- [ ] With a 2.0.1 control panel running in a different signed-in user's session,
      confirm both upgrade and uninstall detect the process and refuse to replace
      files until it exits, even though the legacy global mutex ACL is cross-user
      inaccessible.
- [ ] Re-enable settings, then uninstall. Confirm DNS is healthy, the firewall
      rule is absent, `DrawbridgeService` is gone, the common Startup shortcut is
      removed, and the legacy task is absent.
- [ ] Force cleanup or service deletion to fail during uninstall. Confirm uninstall
      aborts before removing files and restarts the previously running service; if
      restart is also forced to fail, confirm the emergency DNS guidance appears.
- [ ] Confirm `%ProgramData%\Drawbridge` remains intact.
- [ ] Reinstall and confirm lists, rules, mode, PIN, and history return.
- [ ] Legacy case: with ProgramData empty and `%AppData%\Drawbridge` populated,
      launch the app, accept migration, and confirm files are copied (not moved).
- [ ] Confirm migration upgrades `blocklists.json`, hashed list caches/metadata,
      daily logs, the web-monitor flag, and the legacy PBKDF2 PIN, with new ACLs.
      Arbitrary paths, reparse points, untrusted profiles, malformed data, and
      oversize sources must be rejected without partially overwriting live state.
