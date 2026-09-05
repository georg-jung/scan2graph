# Deployment contract

All deployment adapters use the same binary and `KEY=value` configuration:
`scan2graph --config /path/to/scan2graph.env`. `S2G_CONFIG_FILE` also selects
the path; setting precedence remains environment > file > built-in defaults.

Configuration persists. The setup process needs write access to its directory
for atomic file replacement and the `setup-next-start` marker. Jobs and their
temporary files remain ephemeral. Apply configuration by restarting the service;
the wizard currently saves files but does not trigger a restart itself.

## Planned native DSM package

The SPK is not implemented yet. It will run the static binary as an unprivileged
package user, without a Container Manager dependency. Following the
[Synology package filesystem](https://help.synology.com/developer-guide/integrate_dsm/fhs.html):

- Store configuration at `/var/packages/scan2graph/etc/scan2graph.env`, outside
  the replaceable application files in `target`, and preserve it across upgrades.
- Set `S2G_TEMP_DIR=/var/packages/scan2graph/tmp` for ephemeral scans.
- Let DSM own service start/stop, the HTTP reverse proxy and TLS. Keep SMTP
  on the LAN and use unprivileged listener ports.
- Seed the public URL before first boot when a proxy subpath is needed.
- Reuse the application setup wizard for Microsoft settings. The package
  adapter supplies paths and lifecycle integration; it must not duplicate that form.
