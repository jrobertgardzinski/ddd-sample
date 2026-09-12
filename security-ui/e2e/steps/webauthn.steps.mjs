// UI glue for mfa-passkey.feature: a real passkey through the browser, using Chromium's virtual
// authenticator (CDP WebAuthn). THIS is where the protocol's name belongs — the spec speaks the
// user's language ("a device that can hold passkeys"), the glue does the WebAuthn dance: it
// stands up a fake authenticator, enrols, and signs in — exactly what a platform passkey does.

import { Given, Then, When } from '@cucumber/cucumber';
import { expect } from 'playwright/test';
import { proveForEnrol } from './mfa.steps.mjs';
import { credentials } from '../support/account.mjs';
import { UI } from '../support/world.mjs';

Given('the USER has a device that can hold PASSKEYS', async function () {
  const client = await this.page.context().newCDPSession(this.page);
  await client.send('WebAuthn.enable');
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,          // a discoverable credential — sign-in needs no allowCredentials
      hasUserVerification: true,
      isUserVerified: true,          // the authenticator reports UV without a real gesture
      automaticPresenceSimulation: true,
    },
  });
});

Given('the USER has ENROLLED a PASSKEY', async function () {
  // sign in (no factors yet, so the password is enough), then add the passkey from the account page
  await this.page.getByTestId('tab-signin').click();
  await this.page.getByTestId('email').fill(credentials.email);
  await this.page.getByTestId('password').fill(credentials.password);
  await this.page.getByTestId('submit').click();
  await expect(this.page.getByTestId('signed-in-email')).toHaveText(credentials.email);

  await this.page.getByTestId('add-WEBAUTHN').click();
  await proveForEnrol(this);
  // the UI creates the credential and confirms in one gesture — wait for the passkey to appear
  await expect(this.page.getByTestId('factor-list').getByText('passkey')).toBeVisible();
  await this.page.getByTestId('sign-out').click();
});

// "the USER AUTHENTICATES with the correct password" is already defined in mfa.steps.mjs — reuse it.

Then('the USER is signed in by the PASSKEY', async function () {
  // the passkey step runs automatically: the mfa screen shows the passkey prompt, then the
  // authenticator signs the challenge and the session lands — no code was ever typed
  await expect(this.page.getByTestId('signed-in-email')).toHaveText(credentials.email);
  await this.page.getByTestId('sign-out').click();
});

// --- The enrolment answer is not a sign-in ----------------------------------------------------
// No browser in these two steps, deliberately: the danger is exactly someone who has the password
// and does NOT have the device, so they never open the app — they speak HTTP at the service. The
// glue plays that part, because the page would never build this request.

When('the correct password is answered with an ENROLMENT instead of the PASSKEY', async function () {
  const started = await this.backdoor('/authenticate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: credentials.email, password: credentials.password }),
  });
  expect(started.status).toBe(202);
  const { mfaTicket, nextFactor, challengeData } = await started.json();
  expect(nextFactor).toBe('WEBAUTHN');

  // everything below is built from what the 202 just handed out — no signature, no key, because
  // an enrolment envelope carries neither: it is the shape the browser sends when CREATING a passkey
  const clientDataJSON = base64url(JSON.stringify({
    type: 'webauthn.create', challenge: challengeData, origin: UI,
  }));
  const proof = JSON.stringify({
    type: 'webauthn.create', credentialId: 'forged', publicKey: 'forged', clientDataJSON,
  });
  this.enrolmentAnswer = await this.backdoor('/authenticate/factor', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mfaTicket, proof }),
  });
});

Then('the sign-in is refused and no session is issued', async function () {
  expect(this.enrolmentAnswer.status).toBe(401);
  const body = await this.enrolmentAnswer.json();
  expect(body.accessToken).toBeUndefined();
});

function base64url(text) {
  return Buffer.from(text, 'utf8').toString('base64url');
}
