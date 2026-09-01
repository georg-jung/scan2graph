// A scan belongs to the people it was addressed to. Everyone else is told it
// does not exist - the unguessable URLs are never the check.
//
// Every request here is a real browser navigation. Playwright's API request
// context would not do: the session cookie is Secure, so it never leaves the
// Node side over plain HTTP and every URL would answer "sign in", which looks
// exactly like a pass.

import { randomUUID } from 'node:crypto';
import { expect, test } from '@playwright/test';

import { resetFakes } from '../lib/fakes.mjs';
import { makePdf, sendScan } from '../lib/smtp.mjs';
import { signIn, signOut } from '../lib/sign-in.mjs';

test.beforeEach(resetFakes);

test('Bob can neither see nor fetch a scan addressed to Alice', async ({ page }) => {
  const subject = `e2e authorization ${randomUUID().slice(0, 8)}`;
  const codes = await sendScan({
    from: 'web-only@scanner.local',
    to: 'alice@corp.example',
    subject,
    pdf: makePdf(subject),
  });
  expect(codes.body).toBe(250);

  // As Alice: learn both URLs and prove they are live, so the 404s below are
  // evidence about Bob rather than about a wrong URL.
  await signIn(page, 'alice');
  const scanURL = await rowFor(page, subject).getByRole('link').getAttribute('href');
  expect((await page.goto(scanURL)).status()).toBe(200);
  await expect(page.getByRole('heading', { name: subject })).toBeVisible();
  await expect(async () => {
    await page.reload(); // the control appears once the pipeline is done
    await expect(page.locator('a.download')).toHaveCount(1);
  }).toPass({ intervals: [50], timeout: 30_000 });
  const documentURL = await page.locator('a.download').getAttribute('href');
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.locator('a.download').click(),
  ]);
  expect(await download.failure()).toBeNull();

  // As Bob: the same two URLs, in the same browser.
  await signOut(page);
  await signIn(page, 'bob');
  await expect(rowFor(page, subject)).toHaveCount(0);
  expect((await page.goto(scanURL)).status()).toBe(404);
  expect((await page.goto(documentURL)).status()).toBe(404);
});

const rowFor = (page, subject) => page.locator('tr').filter({ hasText: subject });
