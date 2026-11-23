# Design notes

Decisions that shape the code, with the reason, so they are not re-argued by
whoever picks up the next package. Newest first within each section.

## Where the weight is

The scan path itself — `smtpin`, `mimescan`, `docintel`, `graphmail`,
`msapi` — is small, well tested and earns its lines. The weight sits around
it: a configuration surface of ~30 variables with a `_FILE` twin each, four
run modes with a marker file, a job store that books worst-case reservations
before a message is read, and comments that run to essays. The overhaul
targets those, in this order, one pull request each:

1. **Configuration surface.** The printer's sender address *is* the profile;
   knobs nobody would turn become constants.
2. **One way into setup.** `scan2graph` and `scan2graph setup`, nothing else;
   a shorter wizard for the shorter configuration. Carry-overs: the form
   cannot clear a saved SMTP password (so ticking anonymous then fails to
   load), and the setup screenshots other than `setup.png` predate package 1.
3. **Job store and scans page.** Charge what a scan really occupies once it
   has been read; one page listing scans with their downloads inline.

## Decisions

**The sender address selects the features.** The local part of the SMTP
envelope sender is split on every character that is not a letter or digit;
the words `email`, `web` and `ocr` name features. An address naming none of
them gets everything this appliance has configured; one naming some gets
exactly those, and is refused at `MAIL FROM` when it names a feature that is
not configured or names no delivery (`ocr` alone). This replaces
`S2G_PROFILES`: the printer already has one sender address per button, so the
operator configures the behaviour where they press it, and the appliance has
nothing to keep in sync. Sender addresses are not authentication — SMTP AUTH
is — so letting the printer pick is no wider than a profile map was.

**No `_FILE` spellings.** The configuration file the wizard writes is where
secrets live; a second indirection per variable was a container idiom with
no user here. Environment variables still override the file.

**Constants over settings** for things no operator of one printer changes:
Graph and Document Intelligence scopes and API version, worker count (2),
log format (text), SMTP username (`scanner`), the UI's name, and the temp
directory (Go's `os.TempDir`, i.e. `$TMPDIR`). The token endpoint is derived
from the authority URL, so pointing at a test IdP is one setting, not two.
