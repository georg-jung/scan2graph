// The setup wizard, from an appliance that has never been configured to one
// that serves a scan. Three things are proved here and nowhere else: that
// claiming the wizard takes it away from every other browser on the network,
// that "Test connection" tells an operator which of their three credentials
// is the broken one, and that the file it writes is a file the appliance
// actually runs on.
//
// One browser for all three, in order. The wizard belongs to the browser that
// pressed Start until scan2graph is restarted, so a fresh context per test -
// Playwright's default, and a fresh cookie jar - would be locked out of the
// wizard this suite itself claimed.

import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

import { serving as pollSmtp, startAppliance } from '../lib/appliance.mjs';
import { FIXTURE_SECRET, resetFakes } from '../lib/fakes.mjs';
import { signIn } from '../lib/sign-in.mjs';
import { makePdf, sendScan } from '../lib/smtp.mjs';

const e2e = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const WIZARD = 'http://127.0.0.1:18081'; // playwright.config.mjs starts it there
const CONFIG = path.join(e2e, '.tmp', 'wizard', 'scan2graph.env');
const CA = path.join(e2e, '.tmp', 'fake-ca.pem');

// Where the appliance configured here ends up: ports of its own, clear of the
// harness's, and the callback URL the fake app registration has registered
// (e2e/fakes/main.go). Changing either means changing that too.
const APPLIANCE = 'http://127.0.0.1:18082';
const SMTP_PORT = 12526;

// The form as an operator fills it in, pointed at the fakes. The two password
// boxes are kept apart from it, below, because one of them is deliberately
// typed wrong later on.
const FORM = {
  S2G_ENTRA_TENANT_ID: '00000000-0000-0000-0000-0000000000aa',
  S2G_ENTRA_CLIENT_ID: '00000000-0000-0000-0000-000000000001',
  S2G_GRAPH_SENDER: 'scanner@corp.example',
  S2G_ALLOWED_RECIPIENT_DOMAINS: 'corp.example',
  S2G_PUBLIC_BASE_URL: APPLIANCE,
  S2G_HTTP_ADDR: APPLIANCE.replace('http://', ''),
  S2G_SMTP_ADDR: `127.0.0.1:${SMTP_PORT}`,
  S2G_SMTP_USERNAME: 'printer',
  S2G_DI_ENDPOINT: 'https://127.0.0.1:19443',
};

// The two password boxes, which the form never renders back: an empty one
// keeps only a secret the *file* already holds, so until the first save every
// submission has to carry them or it is a configuration with no SMTP password.
const SECRETS = {
  S2G_ENTRA_CLIENT_SECRET: FIXTURE_SECRET,
  S2G_SMTP_PASSWORD: FIXTURE_SECRET,
};

const CHECKS = ['Entra sign-in', 'App-only token', 'Document Intelligence'];

test.describe.configure({ mode: 'serial' });

let page; // the browser that claims the wizard
let appliance; // the serve process the last test starts on the saved file

test.beforeAll(async ({ browser }) => {
  // delivery.spec.mjs leaves Document Intelligence in fail mode, and the OCR
  // at the end of this file would inherit it.
  await resetFakes();
  page = await browser.newPage();
});

test.afterAll(async () => {
  appliance?.child.kill('SIGTERM');
  await page?.close();
});

test('the browser that claims the wizard is the only one that gets it', async ({ browser }) => {
  const other = await browser.newContext();
  const bystander = await other.newPage();

  // Both browsers see the door while nobody holds the key, so the 404s below
  // are evidence about the claim rather than about a wrong URL.
  await page.goto(WIZARD);
  await bystander.goto(WIZARD);
  await expect(bystander.getByRole('button', { name: 'Start configuration' })).toBeVisible();

  await page.getByRole('button', { name: 'Start configuration' }).click();
  await expect(page.getByRole('button', { name: 'Save the configuration file' })).toBeVisible();

  expect((await bystander.goto(`${WIZARD}/setup`)).status()).toBe(404);

  await other.close();
});

test('Test connection passes against the fakes, and singles out a broken secret', async () => {
  await fillForm(FIXTURE_SECRET);
  await testConnection().click();
  for (const name of CHECKS) await expect(result(name)).toHaveText(/\bok\b/i);

  // The whole reason the feature exists: with a secret Entra will not accept,
  // the sign-in check - which needs no secret - still passes, and the two
  // that do need one say what Entra said, in the operator's own words. The
  // fake answers with the sentence real Entra sends, so this asserts the
  // headline claim rather than oauth2's rendering of "invalid_client".
  await fillForm(`${FIXTURE_SECRET}-wrong`);
  await testConnection().click();
  await expect(result('Entra sign-in')).toHaveText(/\bok\b/i);
  for (const name of ['App-only token', 'Document Intelligence']) {
    await expect(result(name)).not.toHaveText(/\bok\b/i);
    await expect(result(name)).toContainText('AADSTS7000215: Invalid client secret provided');
  }
});

test('the appliance runs on the file the wizard writes', async () => {
  await fillForm(FIXTURE_SECRET);
  await page.getByRole('button', { name: 'Save the configuration file' }).click();
  await expect(page.getByRole('heading', { name: 'Saved' })).toBeVisible();
  await expect(page.locator('code')).toHaveText(CONFIG);

  appliance = startAppliance({
    args: ['serve', '--config', CONFIG],
    env: { PATH: process.env.PATH, SSL_CERT_FILE: CA },
    smtpPort: SMTP_PORT,
  });
  await serving();

  const subject = `e2e setup ${randomUUID().slice(0, 8)}`;
  const pdf = makePdf(subject);
  const codes = await sendScan({
    from: 'printer@scanner.local',
    to: 'alice@corp.example',
    subject,
    pdf,
    port: SMTP_PORT,
  });
  expect(codes.body).toBe(250);

  await signIn(page, 'alice', APPLIANCE);
  const row = page.locator('tr').filter({ hasText: subject });
  await expect(async () => {
    await page.reload();
    // textContent, not innerText: the stylesheet capitalizes the status.
    await expect(row.locator('.status')).toHaveText('ready');
  }).toPass({ intervals: [50], timeout: 30_000 });

  await row.getByRole('link').click();
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.locator('a.download').click(),
  ]);
  const chunks = [];
  for await (const chunk of await download.createReadStream()) chunks.push(chunk);
  // Searchable, and made so from this scan: the SMTP port, the Entra app
  // registration and the Document Intelligence endpoint in that file were all
  // used to get here.
  expect(Buffer.concat(chunks).toString())
    .toContain(`OCRED-BY-FAKE ${createHash('sha256').update(pdf).digest('hex')}`);
});

// The third submit button, by the name and value the wizard's form gives it -
// its label is the other half of the interface and not this test's to fix.
const testConnection = () => page.locator('button[name="action"][value="test"]');

// One check's result: the block above the form is a list, one entry per named
// check.
const result = (name) => page.locator('li').filter({ hasText: name });

// fillForm types the whole form, secrets and all, with entraSecret in the
// client secret box. Every submission re-renders the form and empties the two
// password boxes, so each step here fills it in from scratch rather than
// depending on what the last one left behind.
async function fillForm(entraSecret) {
  // The listen address is behind its group's "Rarely needed" disclosure, and
  // a collapsed <details> is not something Playwright will type into.
  await page.locator('details:has(#S2G_HTTP_ADDR) summary').click();
  const boxes = { ...FORM, ...SECRETS, S2G_ENTRA_CLIENT_SECRET: entraSecret };
  for (const [name, value] of Object.entries(boxes)) await page.locator(`#${name}`).fill(value);
}

// serving waits for both listeners: /healthz says the process came up and got
// through OIDC discovery, and the shared socket poll confirms the SMTP port,
// which is bound on a goroutine of its own.
async function serving() {
  await expect(async () => {
    expect(appliance.exited, appliance.log).toBe(false);
    expect((await fetch(`${APPLIANCE}/healthz`)).ok).toBe(true);
  }).toPass({ intervals: [50], timeout: 30_000 });
  await pollSmtp(appliance);
}
