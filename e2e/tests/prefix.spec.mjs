// The appliance published under a subpath prefix, the way a NAS shares its
// hostname with everything else on it: a real scan2graph on a port of its
// own, browsed at /scanner/ with nothing rewriting the path - which is
// exactly what a reverse proxy that forwards it unchanged looks like from
// here. What is proved is that every path the appliance emits carries the
// prefix: the sign-in it registered with Entra, the stylesheet, the links,
// the download, and the scope of the session cookie.

import { randomUUID } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

import { serving, startAppliance } from '../lib/appliance.mjs';
import { FIXTURE_SECRET, resetFakes } from '../lib/fakes.mjs';
import { signIn, signOut } from '../lib/sign-in.mjs';
import { makePdf, sendScan } from '../lib/smtp.mjs';

const e2e = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

// Ports of its own, clear of the other two appliances, and the callback URL
// the fake app registration has registered (e2e/fakes/main.go). Changing
// either means changing that too.
const HOST = 'http://127.0.0.1:18083';
const PREFIX = '/scanner';
const SMTP_PORT = 12527;

// And the wizard, which on a NAS is what the operator meets through that same
// proxy first, before anything is configured: its own port, its own prefix,
// and a seeded configuration file - the only place the prefix can come from
// on a first boot, since a forwarded path and a direct hit look the same from
// inside.
const WIZARD = 'http://127.0.0.1:18084';
const WIZARD_PREFIX = '/scan2graph';
const WIZARD_DIR = path.join(e2e, '.tmp', 'prefix-wizard');

let appliance;
let wizard;

test.beforeAll(async () => {
  await resetFakes();
  appliance = startAppliance({
    args: ['serve'],
    env: {
      PATH: process.env.PATH,
      S2G_HTTP_ADDR: HOST.replace('http://', ''),
      S2G_SMTP_ADDR: `127.0.0.1:${SMTP_PORT}`,
      // With the trailing slash an operator would type: the appliance
      // normalises it away and serves the prefix that is left.
      S2G_PUBLIC_BASE_URL: `${HOST}${PREFIX}/`,
      S2G_TEMP_DIR: path.join(e2e, '.tmp', 'prefix'),
      S2G_LOG_FORMAT: 'text',
      S2G_SMTP_USERNAME: 'printer',
      S2G_SMTP_PASSWORD: FIXTURE_SECRET,
      S2G_ENTRA_TENANT_ID: '00000000-0000-0000-0000-0000000000aa',
      S2G_ENTRA_CLIENT_ID: '00000000-0000-0000-0000-000000000001',
      S2G_ENTRA_CLIENT_SECRET: FIXTURE_SECRET,
      S2G_ENTRA_AUTHORITY_URL: 'http://127.0.0.1:19000/idp',
      S2G_ENTRA_TOKEN_URL: 'http://127.0.0.1:19000/idp/token',
      S2G_JOB_TTL: '30m',
    },
    smtpPort: SMTP_PORT,
  });
  await expect(async () => {
    expect(appliance.exited, appliance.log).toBe(false);
    expect((await fetch(`${HOST}/healthz`)).ok).toBe(true);
  }).toPass({ intervals: [50], timeout: 30_000 });
  await serving(appliance);
});

test.afterAll(() => {
  appliance?.child.kill('SIGTERM');
  wizard?.child.kill('SIGTERM');
});

test('a scan is picked up under the prefix, and nothing points at the root', async ({ page, context }) => {
  const subject = `e2e prefix ${randomUUID().slice(0, 8)}`;
  const codes = await sendScan({
    from: 'printer@scanner.local',
    to: 'alice@corp.example',
    subject,
    pdf: makePdf(subject),
    port: SMTP_PORT,
  });
  expect(codes.body).toBe(250);

  // From the bare prefix, without the trailing slash somebody typing it into
  // the address bar would leave off, through the whole sign-in: the identity
  // provider refuses any redirect URI but the registered, prefixed one.
  await signIn(page, 'alice', `${HOST}${PREFIX}`);
  await expect(page).toHaveURL(`${HOST}${PREFIX}/`);

  // The session cookie reaches this appliance and nothing else on the host.
  const session = (await context.cookies()).find((c) => c.name === 's2g_session');
  expect(session?.path).toBe(PREFIX);

  // The stylesheet is a link the browser has to resolve on its own, so a
  // root-relative one would be a page with no styling and no error anywhere.
  const stylesheet = page.locator('link[rel="stylesheet"]');
  await expect(stylesheet).toHaveAttribute('href', `${PREFIX}/static/style.css`);
  expect((await page.request.get(`${HOST}${PREFIX}/static/style.css`)).status()).toBe(200);

  const row = page.locator('tr').filter({ hasText: subject });
  await expect(async () => {
    await page.reload();
    // textContent, not innerText: the stylesheet capitalizes the status.
    await expect(row.locator('.status')).toHaveText('ready');
  }).toPass({ intervals: [50], timeout: 30_000 });

  const scanHref = await row.getByRole('link').getAttribute('href');
  expect(scanHref.startsWith(`${PREFIX}/scan/`)).toBe(true);
  await row.getByRole('link').click();
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.locator('a.download').click(),
  ]);
  expect(await download.failure()).toBeNull();

  await signOut(page);
  await expect(page.getByRole('link', { name: 'Sign in again' })).toHaveAttribute('href', `${PREFIX}/`);

  // Health answers in both places - the container runtime asks the port, a
  // monitor asks the public URL - while the appliance itself is only under
  // the prefix, which is all the proxy forwards.
  expect((await fetch(`${HOST}${PREFIX}/healthz`)).ok).toBe(true);
  expect((await fetch(`${HOST}/readyz`)).ok).toBe(true);
  expect((await page.request.get(`${HOST}/`)).status()).toBe(404);
});

test('the setup wizard is reached through the proxy path, not the root', async ({ page }) => {
  const config = path.join(WIZARD_DIR, 'scan2graph.env');
  await mkdir(WIZARD_DIR, { recursive: true });
  await writeFile(config, [
    `S2G_HTTP_ADDR=${WIZARD.replace('http://', '')}`,
    `S2G_PUBLIC_BASE_URL=${WIZARD}${WIZARD_PREFIX}/`,
    `S2G_TEMP_DIR=${WIZARD_DIR}`,
    '',
  ].join('\n'));
  wizard = startAppliance({
    args: ['setup', '--config', config],
    env: { PATH: process.env.PATH },
    smtpPort: 0,
  });
  await expect(async () => {
    expect(wizard.exited, wizard.log).toBe(false);
    expect((await fetch(`${WIZARD}/healthz`)).ok).toBe(true);
  }).toPass({ intervals: [50], timeout: 30_000 });

  // Health answers under the prefix here too: the monitor watching the
  // public URL is watching one address whichever mode this is in.
  expect((await fetch(`${WIZARD}${WIZARD_PREFIX}/healthz`)).ok).toBe(true);

  // The proxy's own path, as an operator types it: no trailing slash, no
  // /setup. Both redirects that get from there to the wizard are the
  // appliance's own.
  await page.goto(`${WIZARD}${WIZARD_PREFIX}`);
  await expect(page).toHaveURL(`${WIZARD}${WIZARD_PREFIX}/setup`);
  await expect(page.locator('link[rel="stylesheet"]'))
    .toHaveAttribute('href', `${WIZARD_PREFIX}/static/style.css`);
  expect((await page.request.get(`${WIZARD}${WIZARD_PREFIX}/static/style.css`)).status()).toBe(200);

  // The LAN address the startup banner prints when there is no public URL
  // still lands in the wizard rather than on a 404.
  await page.goto(`${WIZARD}/`);
  await expect(page).toHaveURL(`${WIZARD}${WIZARD_PREFIX}/setup`);

  // Claiming it and reaching the form is the whole point: both presses post
  // to a path the proxy forwards.
  await page.getByRole('button', { name: 'Start configuration' }).click();
  await expect(page).toHaveURL(`${WIZARD}${WIZARD_PREFIX}/setup`);
  await expect(page.getByRole('button', { name: 'Save the configuration file' })).toBeVisible();
  // The value only this page can work out, with the prefix in it.
  await expect(page.locator('.guide code'))
    .toHaveText(`${WIZARD}${WIZARD_PREFIX}/auth/callback`);
});
