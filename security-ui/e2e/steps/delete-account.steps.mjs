// UI glue for delete-account.feature (rule 1 — the immediate lock; the saga's confirmation
// mechanics are wire-owned, tagged @http-only). Closing walks the danger zone: a fresh step-up
// (the full chain — password, then whatever factors the account enrolled) guards the button.
// The access-token proof uses the very token the browser sent to /account/delete.

import { Then, When } from '@cucumber/cucumber';
import { expect } from 'playwright/test';
import { SECURITY } from '../support/world.mjs';
import { credentials } from '../support/account.mjs';

let deletedWithToken = '';

When('the USER requests account DELETION', async function () {
  // DELETE /account/{the caller's own address} since 2026-09-11 — one route for both ways of
  // closing an account, and the address in the path is what says whose closure this is. The glue
  // waited for the old /account/delete and timed out for thirty seconds on a request nobody makes.
  const deleteRequest = this.page.waitForRequest(
      (r) => r.method() === 'DELETE' && r.url().includes('/account/'));
  await this.page.getByTestId('delete-account').click();
  await this.page.getByTestId('delete-password').fill(credentials.password);
  await this.page.getByTestId('delete-start').click();
  // a fresh account's full chain is the password alone; enrolled factors would surface the
  // code input here — this scenario's account is scenario-unique and factor-free
  deletedWithToken = (await deleteRequest).headers()['authorization']?.replace('Bearer ', '') ?? '';
  await expect(this.page.getByTestId('notice')).toContainText('Account closing');
});

Then('the access token no longer authorizes', async function () {
  if (!deletedWithToken) throw new Error('the harness did not capture the access token');
  const r = await fetch(`${SECURITY}/me`, { headers: { Authorization: `Bearer ${deletedWithToken}` } });
  if (r.status !== 401) throw new Error(`a locked account's token still authorizes: ${r.status}`);
});

Then('the email is not yet free to REGISTER', async function () {
  // the wire is quiet on purpose (anti-enumeration): registering answers like a fresh sign-up —
  // what proves the account still exists is the notice mailed to the address
  await this.page.getByTestId('tab-signup').click();
  await this.page.getByTestId('email').fill(credentials.email);
  await this.page.getByTestId('password').fill(credentials.password);
  await this.page.getByTestId('submit').click();
  await expect(this.page.getByTestId('inbox-screen')).toBeVisible();
  const noticed = await this.backdoor(`/test/mailbox/notice?email=${encodeURIComponent(credentials.email)}`);
  if (!noticed.ok) throw new Error('no notice reached the address — was the account really kept?');
  await this.page.getByTestId('back-to-signin').click();
});
