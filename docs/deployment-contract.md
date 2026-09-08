# Deployment contract

All deployment adapters use the same binary and `KEY=value` configuration:
`scan2graph --config /path/to/scan2graph.env`. `S2G_CONFIG_FILE` also selects
the path; setting precedence remains environment > file > built-in defaults.

Configuration persists. The setup process needs write access to its directory
for atomic file replacement and the `setup-next-start` marker. Jobs and their
temporary files remain ephemeral. On normal first boot and marker-armed repair,
**Save and start** writes a valid configuration, closes the wizard listener,
reloads the original configuration source, and starts the appliance in the same
process. Deployment adapters must not restart Docker, DSM, or another supervisor
for this initial mode switch. Startup failures are fatal service errors reported
in the service logs; the Starting response is not a readiness guarantee and the
wizard does not reopen.

Explicit `scan2graph setup` remains save-only and never starts the appliance;
pathless setup remains download-only. Downloading, testing, generating a
password, invalid saves, and failed writes never start it. Apply files saved by
explicit setup or edited externally by restarting the managed service.

## Native DSM package

`spk/` builds a Synology DSM 7 package — `spk/build.sh --version vX.Y.Z` writes
one `.spk` per architecture (`x86_64`, `armv8`, `armv7`) into `dist/`, and
`spk/check.sh` verifies them. It carries the same static binary, runs it as an
unprivileged package user, and needs no Container Manager. Following the
[Synology package filesystem](https://help.synology.com/developer-guide/integrate_dsm/fhs.html):

- Configuration lives at `/var/packages/scan2graph/etc/scan2graph.env`, outside
  the replaceable application files in `target`, and survives upgrades. The
  package seeds it on first install and never rewrites it afterwards;
  uninstalling deletes it, along with the service log, because both hold
  secrets the operator did not choose to leave behind.
- `S2G_TEMP_DIR=/var/packages/scan2graph/tmp` holds ephemeral scans.
- DSM owns the service lifecycle through `scripts/start-stop-status`. The
  initial wizard-to-appliance transition stays inside the process, so nothing
  restarts the DSM service for it; later external file edits and explicit setup
  still require one. The listeners are the unprivileged defaults, HTTP 8080 and
  SMTP 2525, both registered with the DSM firewall — a package that does not run
  as root cannot bind 25, so the printer is pointed at 2525.
- TLS and the reverse proxy are the operator's, via Control Panel → Login Portal
  → Advanced → Reverse Proxy. Seed the public URL before first boot when a proxy
  subpath is needed.
- The application setup wizard remains the only place Microsoft settings are
  entered. The package supplies paths and lifecycle integration and has no
  install wizard of its own.
