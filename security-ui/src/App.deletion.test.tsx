import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App } from './App';
import { SECURITY } from './lib';

/**
 * The delete-account step-up chain, driven through the real component — because the one defect
 * this file pins lived precisely in the wiring, not in any function a unit could call: P18 poz. 8
 * found `submitDeleteCode()` posting to /account/step-up/factor WITHOUT the Authorization header.
 * AuthorizationFilter guards /account/**, so the request died as a 401 before any controller ran,
 * and messageFor translated that 401 into "Wrong code." — the UI blamed the user for a code
 * nobody had checked, and an account with an enrolled factor could never delete itself here.
 *
 * <p>The fetch stub below therefore behaves like the filter: /account/** without a Bearer token
 * answers 401, with one it answers the happy path. The assertion is behavioural — the deletion
 * must actually reach DELETE /account/{the caller's own address}.
 *
 * <p>(No testing-library in this project by design — the e2e suite owns browser flows — so this
 * drives React with jsdom events and `act` directly.)
 */

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

type Recorded = { url: string; init?: RequestInit };

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const authorized = (init?: RequestInit): boolean =>
  Boolean((init?.headers as Record<string, string> | undefined)?.Authorization?.startsWith('Bearer '));

/** The service, as the browser sees it — /account/** guarded exactly like AuthorizationFilter. */
const answer = (url: string, init?: RequestInit): Response => {
  if (url === `${SECURITY}/authenticate`) return json({ accessToken: 'token-123' });
  if (url === `${SECURITY}/me`) {
    return authorized(init)
      ? json({ email: 'alice@example.com', roles: ['USER'], mfaCompliant: true })
      : json({}, 401);
  }
  if (url.startsWith(`${SECURITY}/account/`) && !authorized(init)) return json({}, 401);
  if (url === `${SECURITY}/account/factors`) {
    return json({ have: [{ type: 'EMAIL_CODE', label: 'e-mail code' }], offered: [] });
  }
  if (url === `${SECURITY}/account/recovery-codes`) return json({ unused: 0 });
  if (url === `${SECURITY}/sessions`) {
    return authorized(init) ? json({ sessions: [] }) : json({}, 401);
  }
  if (url === `${SECURITY}/account/step-up`) {
    // the account has a factor, so the chain answers 202 with a ticket, never instant elevation
    return json({ status: 'FACTOR_REQUIRED', stepUpTicket: 'ticket-1' }, 202);
  }
  if (url === `${SECURITY}/account/step-up/factor`) return json({ status: 'ELEVATED' });
  if (url === `${SECURITY}/account/alice%40example.com`) return json({}, 202);
  if (url === `${SECURITY}/logout`) return json({});
  return json({}, 404);
};

const byTestId = (id: string): HTMLElement => {
  const found = document.querySelector(`[data-testid="${id}"]`);
  if (!found) throw new Error(`nothing on screen has data-testid="${id}"`);
  return found as HTMLElement;
};

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

/** Flushes promise chains between renders until the screen satisfies the caller — or fails loudly. */
const until = async (what: string, predicate: () => boolean) => {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (predicate()) return;
    await act(async () => { await Promise.resolve(); });
  }
  throw new Error(`the screen never reached: ${what}`);
};

describe('deleting an account that has an enrolled factor', () => {
  let calls: Recorded[];
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    calls = [];
    vi.stubGlobal('fetch', (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ url, init });
      return Promise.resolve(answer(url, init));
    });
    container = document.createElement('div');
    document.body.appendChild(container);
  });

  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    vi.unstubAllGlobals();
  });

  it('carries the session on the factor proof, so the deletion goes through instead of "Wrong code."', async () => {
    await act(async () => {
      root = createRoot(container);
      root.render(<App />);
    });

    // sign in and land on the account screen
    await typeInto(byTestId('email'), 'alice@example.com');
    await typeInto(byTestId('password'), 'correct horse');
    await submitFormOf(byTestId('submit'));
    await until('the signed-in account screen', () => document.querySelector('[data-testid="delete-account"]') !== null);

    // the step-up chain: password first, then the mailed code
    await click(byTestId('delete-account'));
    await typeInto(byTestId('delete-password'), 'correct horse');
    await click(byTestId('delete-start'));
    await until('the factor-code prompt', () => document.querySelector('[data-testid="delete-code"]') !== null);

    await typeInto(byTestId('delete-code'), '123456');
    await click(byTestId('delete-submit'));

    // the proof call must authenticate itself — AuthorizationFilter guards /account/** and would
    // otherwise answer 401 before any controller saw the (perfectly valid) code
    await until('the deletion request',
      () => calls.some((c) => c.url === `${SECURITY}/account/alice%40example.com` && c.init?.method === 'DELETE'));
    const proof = calls.find((c) => c.url === `${SECURITY}/account/step-up/factor`);
    expect(proof).toBeDefined();
    expect((proof!.init!.headers as Record<string, string>).Authorization).toBe('Bearer token-123');
    expect(document.body.textContent).not.toContain('Wrong code.');
  });
});
