// The rejections a printer can provoke, on the wire. Each test asserts the
// exact reply code the appliance owes the device: anything vaguer would pass
// for a connection that simply broke.

import { expect, test } from '@playwright/test';

import { FIXTURE_SECRET, resetFakes } from '../lib/fakes.mjs';
import { makePdf, sendScan } from '../lib/smtp.mjs';

const subject = 'e2e smtp';
const scan = { from: 'web-only@scanner.local', to: 'alice@corp.example', subject, pdf: makePdf(subject) };

// Not for the recordings - nothing here reads them - but because the last
// delivery test leaves Document Intelligence in fail mode, and the next
// person to add a test here that expects a working pipeline would spend an
// hour on it.
test.beforeEach(resetFakes);

test('an envelope sender with no profile is refused at MAIL FROM', async () => {
  const codes = await sendScan({ ...scan, from: 'stranger@scanner.local' });
  expect(codes.auth).toBe(235);
  expect(codes.mail).toBe(550);
});

test('a recipient outside the allowed domain is refused at RCPT TO', async () => {
  const codes = await sendScan({ ...scan, to: 'alice@elsewhere.example' });
  expect(codes.mail).toBe(250); // the sender was fine; it is the recipient that is not
  expect(codes.rcpt).toBe(550);
});

test('a message past the size limit is refused after DATA', async () => {
  const codes = await sendScan({ ...scan, pdf: makePdf(subject, 2 * 1024 * 1024) });
  expect(codes.data).toBe(354); // the server took the message before it knew
  expect(codes.body).toBe(552);
});

test('a wrong SMTP password is refused at AUTH', async () => {
  const codes = await sendScan({ ...scan, password: `${FIXTURE_SECRET}-wrong` });
  expect(codes.auth).toBe(535);
});
