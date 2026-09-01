// Signing in the way a user does: the appliance bounces the browser to the
// fake identity provider, an account is picked there, and the browser comes
// back with a code the appliance exchanges. Nothing here shortcuts the flow.

import { expect } from '@playwright/test';

// where is the appliance to sign in to; the default is the one this suite is
// configured against, and setup.spec.mjs passes the one the wizard wrote a
// configuration file for.
export async function signIn(page, who, where = '/') {
  await page.goto(where);
  await page.click(`#signin-${who}`);
  await expect(page.getByRole('heading', { name: 'Your scans' })).toBeVisible();
}

export async function signOut(page) {
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Signed out' })).toBeVisible();
}
