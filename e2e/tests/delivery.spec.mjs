// What each sender profile does with a scan, end to end: the printer's SMTP
// transaction, the pipeline, and what the recipient can actually get hold of.

import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

import { serving, startAppliance } from '../lib/appliance.mjs';
import { FIXTURE_SECRET, diSubmissions, graphMessages, resetFakes, setDIMode } from '../lib/fakes.mjs';
import { makePdf, sendScan } from '../lib/smtp.mjs';
import { signIn } from '../lib/sign-in.mjs';

const ALICE = 'alice@corp.example';
const e2e = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

test.beforeEach(resetFakes);

test('a web-only scan is downloadable exactly as it was sent', async ({ page }) => {
  const subject = unique('web-only');
  const pdf = makePdf(subject);
  const codes = await sendScan({ from: 'web-only@scanner.local', to: ALICE, subject, pdf });
  expect(codes.body).toBe(250);

  await signIn(page, 'alice');
  await watchUntil(page, subject, 'ready');
  await openScan(page, subject);

  const downloaded = await downloadDocument(page);
  expect(downloaded.equals(pdf)).toBe(true);
  // A profile without ocr must not have asked Document Intelligence anything.
  expect(await diSubmissions()).toEqual([]);
});

test('an OCR scan says so while it runs and then downloads searchable', async ({ page }) => {
  const subject = unique('ocr-web');
  const pdf = makePdf(subject);
  // Signed in before the scan arrives, so the list is already there to catch
  // the job while the pipeline still has it.
  await signIn(page, 'alice');
  const codes = await sendScan({ from: 'ocr-web@scanner.local', to: ALICE, subject, pdf });
  expect(codes.body).toBe(250);

  const seen = await watchUntil(page, subject, 'ready');
  expect([...seen]).toContain('processing');
  await openScan(page, subject);

  const downloaded = await downloadDocument(page);
  expect(downloaded.toString()).toContain(`OCRED-BY-FAKE ${sha256(pdf)}`);
  // The digest proves it was *this* document that went to OCR, which the
  // number of submissions could not: the client retries.
  expect(await diSubmissions()).toContainEqual({ sha256: sha256(pdf), size: pdf.length });
});

test('an email scan goes out through Graph and never appears on the web', async ({ page }) => {
  const subject = unique('ocr-email');
  const pdf = makePdf(subject);
  const codes = await sendScan({ from: 'ocr-email@scanner.local', to: ALICE, subject, pdf });
  expect(codes.body).toBe(250);

  const message = await mailedWithSubject(subject);
  expect(message.error).toBeUndefined();
  expect(message.sender).toBe('scanner@corp.example');
  expect(message.to).toEqual([ALICE]);
  expect(message.attachments).toHaveLength(1);
  expect(message.attachments[0].filename).toBe('scan.pdf');
  expect(Buffer.from(message.attachments[0].base64, 'base64').toString())
    .toContain(`OCRED-BY-FAKE ${sha256(pdf)}`);

  // The profile has no web capability, so the scan Alice was mailed is not
  // hers to download.
  await signIn(page, 'alice');
  await expect(rowFor(page, subject)).toHaveCount(0);
});

test('a failed OCR fails the scan and never passes the original off as searchable', async ({ page }) => {
  await setDIMode('fail');
  const subject = unique('ocr-failure');
  const pdf = makePdf(subject);
  const codes = await sendScan({ from: 'ocr-web@scanner.local', to: ALICE, subject, pdf });
  expect(codes.body).toBe(250);

  await signIn(page, 'alice');
  await watchUntil(page, subject, 'failed');
  await openScan(page, subject);
  await expect(page.locator('.error'))
    .toHaveText('Text recognition failed, so the scan could not be made searchable.');

  // The pages are still there - what is gone is the claim that they are
  // searchable. This is the shipped behaviour, deliberately.
  const downloaded = await downloadDocument(page);
  expect(downloaded.equals(pdf)).toBe(true);
  expect(downloaded.toString()).not.toContain('OCRED-BY-FAKE');
  expect((await diSubmissions()).map((s) => s.sha256)).toContain(sha256(pdf));
});

// A scan too large for Graph's sendMail, on both sides of the permission that
// decides what becomes of it. Neither appliance can be the harness's: this
// needs an SMTP cap well above sendMail's ceiling, a profile with email and
// without ocr so the PDF that reaches Graph is the one the printer sent rather
// than the fake OCR's, and an app registration on each side of Mail.ReadWrite -
// which is a property of the registration, so the fake grants the permission
// to one of the two client ids it knows (e2e/fakes/main.go). The appliances
// differ in nothing else.
test.describe('a scan too large for sendMail', () => {
  // Past graphmail's 2.25 MB sendMail ceiling, and past the 3.75 MB it puts in
  // one chunk, so the upload has to get a second offset right rather than
  // only the first.
  const SIZE = 4 * 1024 * 1024;
  // Ports of their own, clear of the harness's. Started in beforeAll rather
  // than here: a test file is loaded more than once per run, and a process
  // spawned at load time would be spawned again with nothing to stop it.
  const uploads = { clientID: '00000000-0000-0000-0000-000000000001', http: 18083, smtp: 12527 };
  const sendOnly = { clientID: '00000000-0000-0000-0000-000000000002', http: 18084, smtp: 12528 };
  const both = [uploads, sendOnly];

  test.beforeAll(async () => {
    for (const a of both) a.proc = start(a);
    await Promise.all(both.map((a) => serving(a.proc)));
  });

  test.afterAll(() => {
    for (const a of both) a.proc?.child.kill('SIGTERM');
  });

  test('goes up in chunks and arrives whole where Mail.ReadWrite is granted', async () => {
    const subject = unique('large-upload');
    const pdf = bigPdf(subject, SIZE);
    const codes = await sendScan({ from: 'big@scanner.local', to: ALICE, subject, pdf, port: uploads.smtp });
    expect(codes.body).toBe(250);

    const message = await mailedWithSubject(subject);
    expect(message.error).toBeUndefined();
    expect(message.to).toEqual([ALICE]);
    expect(message.attachments).toHaveLength(1);
    expect(message.attachments[0].filename).toBe('scan.pdf');
    // Byte for byte, not "a message showed up": what the upload path has to
    // get right is every chunk at its own offset, and the fake reassembled
    // this one out of two of them.
    expect(Buffer.from(message.attachments[0].base64, 'base64').equals(pdf)).toBe(true);
    // The permission is granted here, so there is nothing for the operator to
    // do and nothing shouting at them about it.
    expect(uploads.proc.log).not.toContain('Large scans');
  });

  test('gets the too-large notice where it is not, and the operator is told why', async () => {
    const subject = unique('large-notice');
    const codes = await sendScan({
      from: 'big@scanner.local', to: ALICE, subject, pdf: bigPdf(subject, SIZE), port: sendOnly.smtp,
    });
    expect(codes.body).toBe(250);

    const notice = await mailedWithSubject(`Scan not delivered: ${subject}`);
    expect(notice.attachments).toEqual([]);
    expect(notice.body).toContain('The scan is 4.0 MB, which is larger than the 2.2 MB an email can carry.');
    // This appliance accepts scans it must then refuse, which is the one case
    // that gets a banner rather than a log line.
    expect(sendOnly.proc.log).toContain('Grant the Mail.ReadWrite application permission');
  });
});

const unique = (flow) => `e2e ${flow} ${randomUUID().slice(0, 8)}`;
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const rowFor = (page, subject) => page.locator('tr').filter({ hasText: subject });

// watchUntil reloads the list until the scan reaches status, and returns
// every status it saw on the way - the pages carry a meta refresh while a job
// is being worked on, but polling here is what makes the wait bounded and the
// intermediate states observable.
async function watchUntil(page, subject, status) {
  const seen = new Set();
  await expect(async () => {
    await page.reload();
    // textContent, not innerText: the stylesheet capitalizes the status.
    seen.add((await rowFor(page, subject).locator('.status').textContent()).trim());
    expect([...seen]).toContain(status);
  }).toPass({ intervals: [50], timeout: 30_000 });
  return seen;
}

async function openScan(page, subject) {
  await rowFor(page, subject).getByRole('link').click();
  await expect(page.getByRole('heading', { name: subject })).toBeVisible();
}

// Every scan the suite sends carries exactly one PDF, so the detail page
// offers it as a single download control rather than as a list.
async function downloadDocument(page) {
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.locator('a.download').click(),
  ]);
  const chunks = [];
  for await (const chunk of await download.createReadStream()) chunks.push(chunk);
  return Buffer.concat(chunks);
}

// mailedWithSubject is the message the appliance sent through Graph, whichever
// of the two paths carried it: the fake reports a draft-and-upload the same
// way it reports a sendMail.
async function mailedWithSubject(subject) {
  let message;
  await expect(async () => {
    message = (await graphMessages()).find((m) => m.subject === subject);
    expect(message).toBeDefined();
  }).toPass({ timeout: 30_000 });
  return message;
}

// bigPdf is makePdf's document with its padding stamped with its own offset.
// The flat padding would compare equal to itself written at the wrong offset,
// so a scrambled scan would pass the assertion above; this one cannot. The
// first and last bytes are left alone - they are the %PDF- and %%EOF the
// appliance checks for.
function bigPdf(marker, size) {
  const pdf = makePdf(marker, size);
  for (let i = 128; i < pdf.length - 64; i++) pdf[i] = 0x41 + (i % 26);
  return pdf;
}

// start runs a second scan2graph, pointed at the harness's fakes but on
// ports of its own. Its environment is exactly what is listed here - a
// setting it is missing fails these tests rather than being quietly made up
// for.
function start({ clientID, http, smtp }) {
  return startAppliance({
    args: ['serve'],
    smtpPort: smtp,
    env: {
      PATH: process.env.PATH,
      S2G_HTTP_ADDR: `127.0.0.1:${http}`,
      S2G_SMTP_ADDR: `127.0.0.1:${smtp}`,
      S2G_TEMP_DIR: path.join(e2e, '.tmp'),
      S2G_LOG_FORMAT: 'text',
      S2G_SMTP_USERNAME: 'printer',
      S2G_SMTP_PASSWORD: FIXTURE_SECRET,
      S2G_PROFILES: JSON.stringify({ 'big@scanner.local': { email: true } }),
      S2G_ALLOWED_RECIPIENT_DOMAINS: 'corp.example',
      S2G_GRAPH_SENDER: 'scanner@corp.example',
      S2G_GRAPH_BASE_URL: 'http://127.0.0.1:19000/graph',
      S2G_ENTRA_TENANT_ID: '00000000-0000-0000-0000-0000000000aa',
      S2G_ENTRA_CLIENT_ID: clientID,
      S2G_ENTRA_CLIENT_SECRET: FIXTURE_SECRET,
      S2G_ENTRA_TOKEN_URL: 'http://127.0.0.1:19000/idp/token',
      // Above sendMail's ceiling by some margin: nothing can choose a
      // delivery path for a scan the SMTP listener refused to take.
      S2G_MAX_MESSAGE_BYTES: String(8 * 1024 * 1024),
    },
  });
}
