# Drawbridge 2.0

Drawbridge is a Windows parental-control DNS filter. Filtering lives in the
LocalSystem `DrawbridgeService`, starts independently of interactive login,
survives logout, and is covered by Service Control Manager recovery actions.
The WPF app is an unprivileged tray control panel that communicates with the
service only over `127.0.0.1:8054`.

## Projects

- `Drawbridge.Core` — DNS proxy, filtering, protected persistence, PINs,
  block history, Windows DNS integration, and optional LAN dashboard.
- `Drawbridge.Service` — Windows Service host, recovery-safe startup, rolling
  logs, and the localhost JSON control API.
- `Drawbridge.App` — dark WPF dashboard and system-tray control panel.
- `Drawbridge.Core.Tests` — engine regression tests.

All mutable state is stored in `%ProgramData%\Drawbridge`. SYSTEM and
Administrators own writes; standard Users receive read/execute access, except
that the PIN verifier is more tightly protected against offline guessing. The
installer does not remove this directory, so rules and history survive
reinstalls.

## Developer build

Install the .NET 8 SDK (or a newer SDK with the .NET 8 targeting packs), then:

```powershell
dotnet restore .\Drawbridge.sln
dotnet build .\Drawbridge.sln -c Release
dotnet exec --roll-forward Major .\Drawbridge.Core.Tests\bin\Release\net8.0\Drawbridge.Core.Tests.dll
```

The checked-in Windows icon is generated deterministically from the Drawbridge
brand geometry. Regenerate all `.ico` sizes after changing the mark with:

```powershell
.\tools\Generate-BrandAssets.ps1
```

For a non-destructive console smoke test, use an isolated data directory and
unprivileged ports. This does not modify adapter DNS:

```powershell
dotnet exec --roll-forward Major .\Drawbridge.Service\bin\Release\net8.0\Drawbridge.Service.dll `
  --console --data-root .\artifacts\dev-data --dns-port 1053 --api-port 18054
```

The isolated control API can then be checked from another shell:

```powershell
curl.exe http://127.0.0.1:18054/api/status
curl.exe -X POST http://127.0.0.1:18054/api/update-check `
  -H "X-Drawbridge-Client: Drawbridge.App" `
  -H "Content-Type: application/json" -d "{}"
```

Running `--console` without port/data overrides exercises the production
locations and port 53, so it requires an elevated shell. Mutating API calls
require JSON, `X-Drawbridge-Client: Drawbridge.App`, no browser `Origin`, and—
after a PIN is set—a valid `X-Drawbridge-Pin`. Read endpoints remain open on
localhost as specified.

## Release build and installer

Run `build.ps1`. It restores, treats build warnings as errors, executes the
engine harness, cleans stale publish directories, and publishes both
executables self-contained for `win-x64` under `artifacts\publish`. It then
invokes Inno Setup 6.4 or newer when `ISCC.exe` is found. Use `-SkipInstaller` when only
the verified publishes are needed. The installer is written to
`artifacts\installer`.

The installer creates or reconfigures `DrawbridgeService` as delayed automatic
under LocalSystem, applies the 5/15/60-second recovery sequence, and verifies
that it reaches `RUNNING`. Upgrades stop the existing service before replacing
files. Uninstall refuses to remove files if the service cannot stop or if DNS,
firewall, and legacy-task cleanup reports a material failure. ProgramData is
intentionally retained.

Set the parent PIN promptly on a new installation. Until the first PIN exists,
the localhost mutation API is intentionally unauthenticated to match the
bootstrap contract; Windows cannot distinguish a parent process from a child
process at that HTTP boundary. Once created, the PIN hash file is restricted to
SYSTEM and Administrators.

See `TESTING.md` before shipping and `DECISIONS.md` for intentional design
choices made where the product brief left room for interpretation.
