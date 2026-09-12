// Where this page's security service lives, in the order the answer may be given:
//
//  1. window.SECURITY_URL — injected at RUNTIME. The e2e harness sets it before the app boots
//     (Playwright), and a deployment can serve a one-line /ui-config.js that does the same, which
//     is how one built bundle serves more than one environment.
//  2. VITE_SECURITY_URL — baked in at BUILD time for a deployment that would rather bake it.
//  3. the compose stack's address, which is what a human on the dev server wants.
//
// It used to be (1) or the hardcoded default, so a production bundle silently pointed at
// localhost:8080 — nothing consumed dist/ yet, which is the only reason that was not an outage.
export const SECURITY =
  (window as unknown as { SECURITY_URL?: string }).SECURITY_URL
  ?? (import.meta.env?.VITE_SECURITY_URL as string | undefined)
  ?? 'http://localhost:8080';

export type Mode = 'signin' | 'signup' | 'inbox' | 'mfa' | 'me' | 'forgot' | 'reset';
export type Factor = { type: string; label: string };
export type Session = { family: string; expiresAt: string };

export const prettify = (code: string) => code.toLowerCase().replaceAll('_', ' ');

export const factorLabel = (type: string) =>
  ({ EMAIL_CODE: 'e-mail code', SMS_CODE: 'SMS code', TOTP: 'authenticator app', WEBAUTHN: 'passkey' } as Record<string, string>)[type] ?? type;
