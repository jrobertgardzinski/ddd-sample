import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App } from './App';
import { SECURITY } from './lib';

/**
 * What one person leaves behind in a tab for the next one, and what the screen does with a refusal
 * it has not understood. Four defects from the 2026-09-08 review, all of them client-side only:
 *
 * <ul>
 *   <li>UI-1 — the sign-in form kept the previous user's address and password after Sign out.</li>
 *   <li>UI-2 — their recovery codes, shown in the clear exactly once, stayed on the account screen
 *       for whoever signed in next.</li>
 *   <li>UI-4 — every 403 was read as "step up again", so a refusal for any other reason put the
 *       user in an elevation loop that could not end.</li>
 *   <li>UI-5 — the step-up's factor half always rendered a code input, so an account whose factor
 *       is a passkey could not step up at all.</li>
 *   <li>UI-3 — an access token that had simply run out (they live an hour) was reported as "Wrong
 *       current password", on a password that was right.</li>
 *   <li>UI-7 — a handler fired as `void fn()` had nobody to catch a dead service, so the screen
 *       said nothing at all.</li>
 * </ul>
 *
 * <p>Driven through the real component with jsdom, like {@code App.deletion.test.tsx} — no
 * testing-library in this project by design.
 */

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const authorized = (init?: RequestInit): boolean =>
  Boolean((init?.headers as Record<string, string> | undefined)?.Authorization?.startsWith('Bearer '));

/** Who /me answers with — flipped between sign-ins so the second session is visibly another person. */
let signedInAs = 'alice@example.com';
/** What /account/recovery-codes says when the button is pressed. */
let recoveryAnswer: () => Response = () => json({ codes: ['aaa-111', 'bbb-222'] });
/** What the step-up's password half answers. */
let stepUpAnswer: () => Response = () => json({ status: 'ELEVATED' });
/** What the guarded action answers before any elevation. */
let guardedAnswer: () => Response = () => json({ status: 'STEP_UP_REQUIRED' }, 403);

const answer = (url: string, init?: RequestInit): Response => {
  if (url === `${SECURITY}/authenticate`) return json({ accessToken: 'token-123' });
  if (url === `${SECURITY}/me`) {
    return authorized(init) ? json({ email: signedInAs, roles: ['USER'], mfaCompliant: true }) : json({}, 401);
  }
  if (url.startsWith(`${SECURITY}/account/`) && !authorized(init)) return json({}, 401);
  if (url === `${SECURITY}/account/factors`) return json({ have: [], offered: ['EMAIL_CODE'] });
  if (url === `${SECURITY}/account/recovery-codes`) {
    return init?.method === 'POST' ? recoveryAnswer() : json({ unused: 0 });
  }
  if (url === `${SECURITY}/account/step-up`) return stepUpAnswer();
  if (url === `${SECURITY}/account/step-up/factor`) return json({ status: 'ELEVATED' });
  if (url === `${SECURITY}/account/email/request`) return guardedAnswer();
  if (url === `${SECURITY}/sessions`) return authorized(init) ? json({ sessions: [] }) : json({}, 401);
  if (url === `${SECURITY}/logout`) return json({});
  return json({}, 404);
};

const byTestId = (id: string): HTMLElement => {
  const found = document.querySelector(`[data-testid="${id}"]`);
  if (!found) throw new Error(`nothing on screen has data-testid="${id}"`);
  return found as HTMLElement;
};

const present = (id: string) => document.querySelector(`[data-testid="${id}"]`) !== null;

const click = async (el: HTMLElement) =>
  act(async () => {
    el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
  });

const typeInto = async (el: HTMLElement, value: string) => {
  const setValue = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')!.set!;
  await act(async () => {
    setValue.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  });
};

const submitFormOf = async (el: HTMLElement) =>
  act(async () => {
    el.closest('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  });

const until = async (what: string, predicate: () => boolean) => {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (predicate()) return;
    await act(async () => { await Promise.resolve(); });
  }
  throw new Error(`the screen never reached: ${what}`);
};

const signIn = async (email: string, password: string) => {
  await typeInto(byTestId('email'), email);
  await typeInto(byTestId('password'), password);
  await submitFormOf(byTestId('submit'));
  await until('the signed-in account screen', () => present('sign-out'));
};

describe('what a tab keeps between sessions', () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(async () => {
    signedInAs = 'alice@example.com';
    recoveryAnswer = () => json({ codes: ['aaa-111', 'bbb-222'] });
    stepUpAnswer = () => json({ status: 'ELEVATED' });
    guardedAnswer = () => json({ status: 'STEP_UP_REQUIRED' }, 403);
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) =>
      Promise.resolve(answer(String(input), init)));
    container = document.createElement('div');
    document.body.appendChild(container);
    await act(async () => {
      root = createRoot(container);
      root.render(<App />);
    });
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    vi.unstubAllGlobals();
  });

  it('leaves no address and no password in the form after Sign out (UI-1)', async () => {
    await signIn('alice@example.com', 'correct horse');
    await click(byTestId('sign-out'));
    await until('the sign-in form', () => present('password'));

    expect((byTestId('password') as HTMLInputElement).value).toBe('');
    expect((byTestId('email') as HTMLInputElement).value).toBe('');
  });

  it('does not show one user their predecessor’s recovery codes (UI-2)', async () => {
    await signIn('alice@example.com', 'correct horse');
    await click(byTestId('generate-recovery'));
    await until('the codes on screen', () => present('recovery-codes'));
    expect(document.body.textContent).toContain('aaa-111');

    await click(byTestId('sign-out'));
    await until('the sign-in form', () => present('password'));
    signedInAs = 'bob@example.com';
    await signIn('bob@example.com', 'another password');

    expect(document.body.textContent).toContain('bob@example.com');
    expect(document.body.textContent).not.toContain('aaa-111');
    expect(present('recovery-codes')).toBe(false);
  });

  it('does not read every 403 as "step up again" (UI-4)', async () => {
    // a MODERATOR below the MFA floor is refused with a 403 that is NOT a step-up; treating it as
    // one sent them round the elevation loop forever
    guardedAnswer = () => json({ error: 'MFA_REQUIRED' }, 403);
    await signIn('alice@example.com', 'correct horse');

    await typeInto(byTestId('new-email'), 'moved@example.com');
    await submitFormOf(byTestId('change-email-submit'));
    await until('an answer on screen', () => present('notice'));

    expect(present('enrol-stepup')).toBe(false);
  });

  it('calls an expired session what it is, instead of blaming the password (UI-3)', async () => {
    await signIn('alice@example.com', 'correct horse');
    // the hour is up: every call carrying the token now answers 401
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === `${SECURITY}/account/password`) return Promise.resolve(json({}, 401));
      return Promise.resolve(answer(url, init));
    });

    await typeInto(byTestId('current-password'), 'correct horse');
    await typeInto(byTestId('new-password'), 'a brand new one');
    await submitFormOf(byTestId('change-password-submit'));
    await until('the sign-in form', () => present('password') && present('notice'));

    expect(byTestId('notice').textContent).toContain('expired');
    expect(document.body.textContent).not.toContain('Wrong current password');
  });

  it('says so when the service cannot be reached, instead of going quiet (UI-7)', async () => {
    await signIn('alice@example.com', 'correct horse');
    vi.stubGlobal('fetch', () => Promise.reject(new TypeError('Failed to fetch')));

    await click(byTestId('generate-recovery'));
    await until('an answer on screen', () => present('notice'));

    expect(byTestId('notice').textContent).toContain('unreachable');
  });

  it('asks a passkey account for its passkey, not for a code (UI-5)', async () => {
    stepUpAnswer = () => json({ status: 'FACTOR_REQUIRED', stepUpTicket: 't-1', nextFactor: 'WEBAUTHN',
      challengeData: 'bm9uY2U' }, 202);
    // the authenticator is not available in jsdom: the prompt fails, and the panel must still be
    // the passkey one — a code input here is the defect
    vi.stubGlobal('navigator', { ...navigator, credentials: { get: () => Promise.reject(new Error('no authenticator')) } });
    await signIn('alice@example.com', 'correct horse');

    await typeInto(byTestId('new-email'), 'moved@example.com');
    await submitFormOf(byTestId('change-email-submit'));
    await until('the step-up panel', () => present('enrol-stepup'));
    await typeInto(byTestId('enrol-stepup-password'), 'correct horse');
    await click(byTestId('enrol-stepup-submit'));
    await until('the passkey half of the step-up', () => present('enrol-stepup-passkey'));

    expect(present('enrol-stepup-code')).toBe(false);
  });
});
