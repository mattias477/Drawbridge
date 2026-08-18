# Drawbridge 2.0 design decisions

## Service-owned state

The service is the only writer of filtering configuration and system state.
The WPF app never reads `%ProgramData%` directly and never loads the engine
assembly. This keeps privilege boundaries explicit and prevents two processes
from racing while saving settings.

## Local API shapes

The WPF client sends `{ "value": ... }` for list/rule changes, `{ "mode":
... }`, `{ "enabled": ... }`, and `{ "pin": ... }`. Collection mutations also
accept a bare JSON string or the descriptive aliases `url`/`domain` to keep
manual diagnostics compatible. Responses use predictable camel-case JSON.
Unknown routes return JSON 404 responses. Request concurrency, body size, and
body-read time are bounded; mutations are serialized so opposite system
changes cannot interleave.

Loopback is not treated as a browser security boundary. Every mutation,
including PIN verification, requires the constant desktop-client header and
`application/json` when a body is present; requests carrying an `Origin` are
rejected. This forces browser callers through a CORS preflight that the service
does not grant. When a PIN exists, other mutations additionally require
`X-Drawbridge-Pin`; guesses are globally serialized and wrong attempts take at
least 1.5 seconds. Reads remain open exactly as required by the localhost API
contract.

PIN verification is the one mutating-looking endpoint exempt from the
PIN-authentication rule: a locked client must be able to prove the PIN before
it can possess an authenticated PIN header. It is not exempt from the desktop
client and JSON checks. When a PIN already exists, changing or removing it
requires `X-Drawbridge-Pin`.

Before the first PIN is set, the literal API contract leaves mutations
unauthenticated. A loopback HTTP service has no reliable parent-versus-child
identity, so the installer launches the app for the installing parent and the
documentation calls out setting the PIN immediately. The stored verifier is
given a stricter SYSTEM/Administrators-only ACL than general ProgramData state,
preventing a standard child from taking the hash away for offline guessing.

## Interactive tray lifecycle

Filtering starts in the LocalSystem service at boot, independently of any user
session. The installer separately places an all-users Startup shortcut that
launches the as-invoker WPF control panel with `--startup` at interactive logon.
That mode creates the notification icon and begins polling without painting the
dashboard or showing a login balloon. A per-session mutex permits one tray icon
in each concurrently signed-in Windows session while suppressing duplicates in
the same session. Each process also holds a non-exclusive global marker with an
Authenticated-Users synchronize-only ACL so the elevated installer can detect
tray processes in other sessions before replacing shared files. Marker failure
is diagnostic-only and cannot suppress the per-session tray. The unsafe elevated
v1 scheduled task remains a cleanup-only legacy artifact.

## DNS lifecycle

When a production service configuration is genuinely absent, DNS routing
defaults on even if an upgrade or legacy import has already populated
ProgramData. A saved explicit off preference normally wins. The one exception is
an unversioned 2.0 configuration found during verified repair of the 2.0 empty-DACL
defect; that affected state is re-enabled once during upgrade. Explicit
console-test roots never change adapter DNS by default.

The ProgramData root receives one exact inheritable ACL. Existing descendants are
repaired through identity-locked, no-follow handles; reparse points and hardlinks
are rejected, ownership is restored to SYSTEM, and the PIN is secured before any
ordinary descendant. Recursive `/inheritance:r` is forbidden because it can leave
ordinary files with an empty DACL and destroy restart persistence.

Externally lowering the bridge restores automatic adapter DNS before stopping
the listeners; if restoration cannot be verified, the stop is rejected. A
graceful SCM stop also attempts restoration without clearing the saved desired
state, so the next service start can raise and route again. If all initial bind
attempts fail, configuration-owned routing is restored unconditionally and the
service keeps retrying in maintenance mode. These fail-safe paths avoid leaving
the machine pointed at a dead loopback resolver.

DNS startup binds all four required endpoints as one operation. If any bind
fails, successfully opened sockets are disposed before the service retries;
Drawbridge never reports a partially healthy bridge.

Remote blocklist sources are limited to public HTTPS destinations. Each DNS
resolution and every manual redirect hop is checked for loopback, private,
link-local, multicast, or unspecified addresses. This intentionally excludes
private/self-hosted lists from the standard UI because fetching them as
LocalSystem would create an SSRF path into the local network.

## Configuration and logs

`settings.json` contains mode, list URLs, and user rules.
`service-config.json` contains DNS-routing and LAN-dashboard preferences.
Cache metadata is kept beside each URL-keyed cache file. Writes use a temporary
file followed by an atomic replace/move to reduce corruption after power loss.

Block history is append-only, one UTF-8 file per local calendar day. Ninety days
of detail are retained, while a separate cumulative counter preserves the
literal all-time total after old daily files are pruned. Retention is applied at
startup and when a new block is recorded. Operational service logs use a
separate `service-yyyy-MM-dd.log` series and prune on day rollover.

## LAN dashboard

The monitor serves a small self-contained HTML page and JSON status endpoint.
Successful PIN login creates a cryptographically random, memory-only,
HttpOnly/SameSite session cookie. Sessions expire after 8 hours and are lost
when the service restarts. The dashboard exposes status/history only; filter
mutations remain localhost-only.

## Legacy migration

The service records first-run migration eligibility before seeding defaults;
the app therefore does not race service creation of ProgramData. After consent,
the app only asks the API to migrate `%AppData%\Drawbridge`; it never writes
ProgramData itself. The LocalSystem service accepts only a source discovered
under a real Windows ProfileList entry, rejects reparse points and oversize
inputs, stages and validates recognized settings/cache/PIN/log data, and copies
rather than moves it so new ACLs apply. Unknown legacy files are not imported.

Legacy `blocklists.json`, URL-hash cache files and metadata, daily logs, the web
monitor flag, and the v1 PBKDF2 PIN record are converted during import while the
source remains untouched. The protected PIN is published through the same
restricted-file path used for new PINs.

## Dependencies

DNS wire handling, JSON HTTP endpoints, chart rendering, icons, and password
storage are implemented with the .NET platform. The only package references
are from `Microsoft.Extensions.*`, as required.
