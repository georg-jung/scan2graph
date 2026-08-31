// What each sender profile does with a scan, end to end: the printer's SMTP
// transaction, the pipeline, and what the recipient can actually get hold of.

import { createHash, randomUUID } from 'node:crypto';
import { expect, test } from '@playwright/test';

import { diSubmissions, graphMessages, resetFakes, setDIMode } from '../lib/fakes.mjs';
import { makePdf, sendScan } from '../lib/smtp.mjs';
import { signIn } from '../lib/sign-in.mjs';

const ALICE = 'alice@corp.example';

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

  let message;
  await expect(async () => {
    message = (await graphMessages()).find((m) => m.subject === subject);
    expect(message).toBeDefined();
  }).toPass({ timeout: 30_000 });

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

async function downloadDocument(page) {
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.locator('ul.docs a').click(),
  ]);
  const chunks = [];
  for await (const chunk of await download.createReadStream()) chunks.push(chunk);
  return Buffer.concat(chunks);
}
