// End-to-end configuration: build and run the real appliance and the real
// fakes, then drive them from one worker at a time.
//
// Everything the appliance needs is set here, so `npm test` is the whole
// command and nothing has to be running beforehand.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from '@playwright/test';

import { FIXTURE_SECRET } from './lib/fakes.mjs';

const e2e = path.dirname(fileURLToPath(import.meta.url));
const tmp = path.join(e2e, '.tmp');

// The second appliance: the setup wizard, on a fresh install, seeded with
// only the S2G_* settings the form has no box for - where it listens, and
// this harness's pointers at the fakes. Written afresh on every start,
// because the suite saves a whole configuration over it.
const wizardDir = path.join(tmp, 'wizard');
const wizardConfig = path.join(wizardDir, 'scan2graph.env');
const wizardSeed = [
  'S2G_HTTP_ADDR=127.0.0.1:18081',
  `S2G_TEMP_DIR=${wizardDir}`,
  'S2G_ENTRA_AUTHORITY_URL=http://127.0.0.1:19000/idp',
  'S2G_ENTRA_TOKEN_URL=http://127.0.0.1:19000/idp/token',
  'S2G_GRAPH_BASE_URL=http://127.0.0.1:19000/graph',
];

export default defineConfig({
  testDir: './tests',
  // One appliance, one job store, one set of recordings in the fakes: the
  // suite is serial by construction.
  fullyParallel: false,
  workers: 1,
  // A test here signs in, waits for a scan through OCR and downloads it; the
  // waits inside are bounded well below this, so hitting it means something
  // is actually stuck.
  timeout: 60_000,
  forbidOnly: !!process.env.CI,
  // The HTML report is what CI uploads when the suite fails; open: 'never'
  // keeps `npm test` from launching a browser on a developer's machine.
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://127.0.0.1:18080',
    acceptDownloads: true,
    trace: 'retain-on-failure',
  },

  // Never reuse either server. The fakes mint a fresh certificate on every
  // start and Go caches SSL_CERT_FILE the first time it builds a root pool,
  // so an appliance left over from an earlier run answers every Document
  // Intelligence call with "certificate signed by unknown authority". The
  // two processes live and die together.
  webServer: [
    {
      command: `cd .. && go build -o e2e/.bin/fakes ./e2e/fakes && exec e2e/.bin/fakes -cert-file "${path.join(tmp, 'fake-ca.pem')}" -secret "${FIXTURE_SECRET}"`,
      url: 'http://127.0.0.1:19000/idp/.well-known/openid-configuration',
      reuseExistingServer: false,
      timeout: 120_000,
    },
    {
      command: 'cd .. && go build -o e2e/.bin/scan2graph ./cmd/scan2graph && exec e2e/.bin/scan2graph',
      url: 'http://127.0.0.1:18080/healthz',
      reuseExistingServer: false,
      timeout: 120_000,
      env: {
        S2G_HTTP_ADDR: '127.0.0.1:18080',
        S2G_SMTP_ADDR: '127.0.0.1:12525',
        S2G_PUBLIC_BASE_URL: 'http://127.0.0.1:18080',
        S2G_TEMP_DIR: tmp,
        S2G_LOG_FORMAT: 'text',
        S2G_LOG_LEVEL: 'info',
        S2G_SMTP_USERNAME: 'printer',
        S2G_SMTP_PASSWORD: FIXTURE_SECRET,
        S2G_PROFILES: JSON.stringify({
          'web-only@scanner.local': { web: true },
          'ocr-web@scanner.local': { web: true, ocr: true },
          'ocr-email@scanner.local': { email: true, ocr: true },
        }),
        S2G_ALLOWED_RECIPIENT_DOMAINS: 'corp.example',
        S2G_GRAPH_SENDER: 'scanner@corp.example',
        S2G_GRAPH_BASE_URL: 'http://127.0.0.1:19000/graph',
        S2G_DI_ENDPOINT: 'https://127.0.0.1:19443',
        S2G_ENTRA_TENANT_ID: '00000000-0000-0000-0000-0000000000aa',
        S2G_ENTRA_CLIENT_ID: '00000000-0000-0000-0000-000000000001',
        S2G_ENTRA_CLIENT_SECRET: FIXTURE_SECRET,
        S2G_ENTRA_AUTHORITY_URL: 'http://127.0.0.1:19000/idp',
        S2G_ENTRA_TOKEN_URL: 'http://127.0.0.1:19000/idp/token',
        S2G_JOB_TTL: '30m',
        // Deliberately small, so the resource-limit rejection can be
        // provoked with a 2 MB message instead of a 40 MB one.
        S2G_MAX_MESSAGE_BYTES: '1048576',
        SSL_CERT_FILE: path.join(tmp, 'fake-ca.pem'),
      },
    },
    {
      // The same binary as above in a different mode: the servers are started
      // one after another, so building it twice is a cache hit and not a race.
      command: `cd .. && go build -o e2e/.bin/scan2graph ./cmd/scan2graph && mkdir -p "${wizardDir}" && printf '%s\\n' ${wizardSeed.map((line) => `'${line}'`).join(' ')} > "${wizardConfig}" && exec e2e/.bin/scan2graph setup --config "${wizardConfig}"`,
      url: 'http://127.0.0.1:18081/healthz',
      reuseExistingServer: false,
      timeout: 120_000,
      // Everything else this appliance reads is in the file above; the
      // certificate cannot be, since the wizard's Document Intelligence
      // check speaks TLS to a fake that mints a new one on every start.
      env: {
        SSL_CERT_FILE: path.join(tmp, 'fake-ca.pem'),
      },
    },
  ],
});
