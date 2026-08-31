// A printer, by hand: SMTP over a raw socket, so the suite exercises the real
// listener over a real TCP connection and sees the real reply codes. A mail
// library would hide exactly the rejections the SMTP flows are about, and
// would not let a test send a message the server is supposed to refuse.

import { createConnection } from 'node:net';

import { FIXTURE_SECRET } from './fakes.mjs';

const SERVER = { host: '127.0.0.1', port: 12525 };
const BOUNDARY = 'scan2graph-e2e-boundary';

// sendScan plays one whole SMTP transaction and returns the reply code of
// every step it reached: auth, mail, rcpt, data (the 354) and body (the
// reply to the final dot). It never throws on a rejection - the dialogue
// simply stops at the first 4xx/5xx, leaving the later fields undefined - so
// a test can assert on the exact code.
export async function sendScan({ from, to, subject, pdf, password = FIXTURE_SECRET }) {
  const codes = {};
  const s = new Session(await connect());
  try {
    await s.read(); // greeting
    await s.cmd('EHLO printer.local');

    await s.cmd('AUTH LOGIN'); // 334, username challenge
    await s.cmd(base64('printer')); // 334, password challenge
    codes.auth = await s.cmd(base64(password));
    if (failed(codes.auth)) return codes;

    codes.mail = await s.cmd(`MAIL FROM:<${from}>`);
    if (failed(codes.mail)) return codes;
    codes.rcpt = await s.cmd(`RCPT TO:<${to}>`);
    if (failed(codes.rcpt)) return codes;
    codes.data = await s.cmd('DATA');
    if (failed(codes.data)) return codes;

    // Dot-stuffing is part of the protocol, not an optimisation: a body line
    // that begins with a dot has to be doubled or it ends the message early.
    const message = mimeMessage({ from, to, subject, pdf });
    codes.body = await s.cmd(message.replace(/^\./gm, '..') + '.');
    return codes;
  } finally {
    s.socket.end('QUIT\r\n');
  }
}

// makePdf builds something the appliance will accept as a scan: it has to
// start with %PDF- and carry %%EOF near its end, and it carries a marker so a
// test can tell its own document apart from any other. size pads it out, for
// the message-too-large rejection.
export function makePdf(marker, size = 1024) {
  const head = `%PDF-1.7\n% scan2graph-e2e ${marker}\n1 0 obj<</Type/Catalog>>endobj\n`;
  const tail = '\ntrailer<</Root 1 0 R>>\n%%EOF\n';
  const padding = '%'.repeat(Math.max(0, size - head.length - tail.length));
  return Buffer.from(head + padding + tail, 'ascii');
}

function mimeMessage({ from, to, subject, pdf }) {
  return [
    `From: Printer <${from}>`,
    `To: <${to}>`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/mixed; boundary="${BOUNDARY}"`,
    '',
    `--${BOUNDARY}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Scanned document attached.',
    `--${BOUNDARY}`,
    'Content-Type: application/pdf',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="scan.pdf"',
    '',
    pdf.toString('base64').replace(/(.{76})/g, '$1\r\n'),
    `--${BOUNDARY}--`,
    '',
  ].join('\r\n');
}

// Session speaks the line protocol: write a command, read one reply, return
// its code. Replies may be multi-line (EHLO), which is why this reads until a
// line whose code is followed by a space rather than a hyphen.
class Session {
  #buffer = '';
  #waiting = null;

  constructor(socket) {
    this.socket = socket;
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => {
      this.#buffer += chunk;
      this.#answer();
    });
    socket.on('error', (err) => this.#abort(err));
    socket.on('close', () => this.#abort(new Error('the server closed the connection')));
  }

  cmd(line) {
    this.socket.write(line + '\r\n');
    return this.read();
  }

  read() {
    return new Promise((resolve, reject) => {
      this.#waiting = { resolve, reject };
      this.#answer();
    });
  }

  #answer() {
    if (!this.#waiting) return;
    const lines = this.#buffer.split('\r\n');
    for (let i = 0; i < lines.length - 1; i++) {
      if (!/^\d{3}(\s|$)/.test(lines[i])) continue; // a continuation line
      this.#buffer = lines.slice(i + 1).join('\r\n');
      const waiting = this.#waiting;
      this.#waiting = null;
      waiting.resolve(Number(lines[i].slice(0, 3)));
      return;
    }
  }

  #abort(err) {
    const waiting = this.#waiting;
    this.#waiting = null;
    waiting?.reject(err);
  }
}

function connect() {
  return new Promise((resolve, reject) => {
    const socket = createConnection(SERVER);
    socket.once('error', reject);
    socket.once('connect', () => resolve(socket));
  });
}

const failed = (code) => code >= 400;
const base64 = (s) => Buffer.from(s, 'utf8').toString('base64');
