# scan2graph

A small, self-contained LAN gateway that turns "scan to email" from old
printers/scanners into modern document delivery: it accepts the printer's SMTP
message, extracts the PDF attachments, optionally runs them through Azure
Document Intelligence OCR (searchable PDF), and then either sends them onwards
with Microsoft Graph, exposes them temporarily in a small Entra-authenticated
web UI, or both.

Many multifunction printers can only speak unauthenticated SMTP to a server on
the local network. Microsoft 365 no longer accepts that. scan2graph is the
missing piece in between — one container, no database, no queue, no persistent
state.

> **Status:** under active development. The repository is bootstrapped;
> features land package by package (see the open pull requests).

## How it works

```
┌─────────┐  SMTP :25→:2525   ┌──────────────────────┐  Azure Document Intelligence
│ printer │ ────────────────► │                      │ ◄──► prebuilt-read, searchable PDF
└─────────┘                   │      scan2graph      │
                              │  (single container)  │  Microsoft Graph
┌─────────┐  HTTPS            │                      │ ◄──► sendMail (MIME)
│ browser │ ──► reverse proxy ─► HTTP :8080          │
└─────────┘     (TLS here)    └──────────────────────┘
```

1. The printer sends the scan to scan2graph over plain LAN SMTP.
2. The **SMTP envelope sender** selects a *sender profile*, i.e. what should
   happen with the scan.
3. The **SMTP envelope recipients** identify the *people* the scan is for.
4. PDFs are extracted, optionally OCRed, and then mailed via Microsoft Graph
   and/or offered for download in the web UI for a limited time.

TLS is terminated by an existing reverse proxy; scan2graph itself speaks plain
HTTP and does not manage certificates.

## Sender profiles vs. recipient identity

Printers usually offer two independent address books: the "from" address of the
device and a list of destination addresses. scan2graph uses them for two
different purposes, and it never looks at the MIME `From:`/`To:` headers.

* **Envelope sender → feature profile.** Configure one printer sender address
  per feature combination, for example `scan-web-ocr@scanner.local`. Unknown
  senders are rejected.
* **Envelope recipients → users.** The recipient addresses are matched against
  the signed-in Entra user (email / UPN, plus an optional alias mapping for
  printers that can only store shortened addresses).

A profile is a combination of three independent capabilities:

| capability | effect                                                        |
| ---------- | ------------------------------------------------------------- |
| `ocr`      | run each PDF through Azure Document Intelligence (searchable PDF) |
| `email`    | send the resulting PDFs via Microsoft Graph to the recipients  |
| `web`      | make the resulting PDFs downloadable in the web UI for a while |

```json
{
  "scan-email-ocr@scanner.local": { "email": true,  "web": false, "ocr": true  },
  "scan-web-ocr@scanner.local":   { "email": false, "web": true,  "ocr": true  },
  "scan-web@scanner.local":       { "email": false, "web": true,  "ocr": false }
}
```

## Reliability model (please read)

scan2graph is intentionally **ephemeral**. Once the printer has received SMTP
`250`, the scan lives only in this process: in-memory metadata plus temporary
files owned by the application. There is no database, no durable queue and no
persistent volume.

If the container crashes or is restarted before delivery, the scan is gone and
the document has to be scanned again. That is a deliberate v1 trade-off for an
appliance that otherwise needs zero operational care — the paper original is
still lying on the scanner glass.

Web-visible scans expire after a configurable TTL (about an hour by default) and
their temporary files are deleted. Email-only scans are deleted immediately
after successful delivery.

## Security assumptions

* The SMTP listener is meant for a **restricted LAN segment** and speaks plain
  TCP without TLS, because that is all these devices can do. It does support
  SMTP AUTH (PLAIN/LOGIN); if you do not configure credentials, scan2graph
  generates an ephemeral password at startup and prints it. Running without
  authentication is possible but has to be opted into explicitly.
  Incoming data is treated as untrusted regardless, and is subject to strict
  size, nesting and count limits.
* scan2graph is **not** a mail relay: it only ever sends *new* messages, to
  envelope recipients that pass a mandatory recipient-domain allowlist.
* The web UI requires Entra sign-in; every download re-checks server-side that
  the signed-in user was an envelope recipient of that scan. Unguessable IDs are
  a defence in depth measure, never the authorization mechanism.
* HTTPS, HSTS and the public hostname are the reverse proxy's job.

## Non-goals

No database, no durable queue, no message broker, no Azure/Graph SDKs, no SPA or
frontend build pipeline, no PDF rendering stack, no admin UI, no generic SMTP
relaying, and no HTTPS/ACME inside the container.

## Development

```bash
go build ./...
go test ./...
docker build -t scan2graph .
```

## License

MIT — see [LICENSE](LICENSE).
