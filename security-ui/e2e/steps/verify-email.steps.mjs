// UI glue for verify-email.feature. The act under test is following the mailed link — the app
// reads `?verify=<token>` at boot and POSTs it — so the scenarios navigate exactly like a mail
// client would. Requesting a (re-)verification is setup, done over the same backdoor wire the
// JVM glue uses in-process. "Verified" is proven the way a user sees it: signing in works.

import { Given, Then, When } from '@cucumber/cucumber';
import { expect } from 'playwright/test';
import { UI } from '../support/world.mjs';
import { credentials } from '../support/account.mjs';
import { signInCompletingMfa } from './mfa.steps.mjs';

Given('the USER requested EMAIL VERIFICATION', async function () {
  const response = await this.backdoor('/verify-email/request', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: credentials.email }),
  });
  if (response.status !== 202) throw new Error(`verification request failed: ${response.status}`);
});

When('the USER VERIFIES the EMAIL with the VERIFICATION TOKEN from the link', async function () {
  const token = await this.verificationTokenFor(credentials.email);
  if (!token) throw new Error('no verification token was e-mailed');
  await this.page.goto(`${UI}/?verify=${encodeURIComponent(token)}`);
});

When('the USER VERIFIES the EMAIL with a garbage VERIFICATION TOKEN', async function () {
  await this.page.goto(`${UI}/?verify=garbage-token`);
});

Then('the EMAIL is verified', async function () {
  await expect(this.page.getByTestId('notice')).toContainText('E-mail verified');
  // the proof a user cares about: signing in now works (completing MFA if the shared account
  // has enrolled a factor in an earlier scenario — accounts deliberately persist)
  await signInCompletingMfa(this);
  await this.page.getByTestId('sign-out').click();
});

Then('the VERIFICATION is rejected', async function () {
  await expect(this.page.getByTestId('notice')).toContainText('already used or replaced');
});

Then('a VERIFICATION link has been e-mailed to the USER', async function () {
  const token = await this.verificationTokenFor(credentials.email);
  if (!token) throw new Error('expected registration to e-mail a verification link automatically');
});

// --- Requesting a link for an already verified address ----------------------------------------
// The request half is setup and attack alike: it is a public endpoint anybody can POST to, so the
// glue posts it — a page would only ever aim it at the signed-in user's own address.

Given('the USER has VERIFIED the EMAIL', async function () {
  const token = await this.verificationTokenFor(credentials.email);
  if (!token) throw new Error('no verification token was e-mailed at registration');
  const response = await this.backdoor('/verify-email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  });
  if (response.status !== 200) throw new Error(`failed to seed a verified address: ${response.status}`);
});

When('EMAIL VERIFICATION is requested again for that EMAIL', async function () {
  this.tokenBeforeTheRequest = await this.verificationTokenFor(credentials.email);
  this.verificationRequest = await this.backdoor('/verify-email/request', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: credentials.email }),
  });
});

Then('the request is accepted as quietly as any other', async function () {
  expect(this.verificationRequest.status).toBe(202);
  expect((await this.verificationRequest.json()).status).toBe('VERIFICATION_LINK_SENT');
});

Then('the EMAIL is still verified', async function () {
  // what the owner would notice: the account still signs in
  await signInCompletingMfa(this);
  await this.page.getByTestId('sign-out').click();
});

Then('no new VERIFICATION link was e-mailed', async function () {
  expect(await this.verificationTokenFor(credentials.email)).toBe(this.tokenBeforeTheRequest);
});
