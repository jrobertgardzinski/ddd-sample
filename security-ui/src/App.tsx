import { useEffect, useState } from 'react';
import { bodyOf, HttpError, messageFor, request } from './api';
import { assertPasskey, enrolPasskey } from './webauthn';
import { Factor, Mode, SECURITY, Session, factorLabel, prettify } from './lib';
import { AccountScreen } from './AccountScreen';
import { MfaScreen } from './MfaScreen';
import { ForgotScreen, InboxScreen, ResetScreen, SignInUpScreen } from './EntryScreens';

/**
 * The auth service's own face: sign in (single- or multi-factor), create an account, the "check
 * your mailbox" screen, confirming a mailed verification link, managing sign-in factors, and /me.
 * Deliberately plain — its real job is being the specs' third entry point (the cucumber-js +
 * Playwright glue drives the same features the JVM runners do). React, like the meme gallery.
 *
 * <p>This component owns ALL state and behaviour; the screens (AccountScreen, MfaScreen, the
 * entry screens) are presentational and receive it grouped by concern. The data-testids that the
 * e2e glue clicks live in the screen files.
 */
/**
 * One broken rule as the wire sends it: {CODE: the parameter in force} — or {CODE: true} where the
 * rule has none. E-mail and password answer in the SAME shape, so one renderer serves both.
 */
const renderFieldError = (error: Record<string, unknown>) => {
  const [code, parameter] = Object.entries(error)[0];
  const shown = Array.isArray(parameter) ? parameter.join(', ') : String(parameter);
  return <li key={code}>{prettify(code)}{parameter === true ? '' : `: ${shown}`}</li>;
};

export function App() {
  const [mode, setMode] = useState<Mode>('signin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [me, setMe] = useState('');
  const [token, setToken] = useState('');
  const [roles, setRoles] = useState<string[]>([]);
  const [compliant, setCompliant] = useState(true);
  const [floor, setFloor] = useState({ required: 1, have: 1 });
  const [notice, setNotice] = useState<string | null>(null);
  const [emailErrors, setEmailErrors] = useState<Record<string, unknown>[]>([]);
  // one entry per failed rule: { CODE: parameter in force } — e.g. { MIN_LENGTH_NOT_MET: 12 },
  // or { CODE: true } for a rule without a parameter
  const [passwordErrors, setPasswordErrors] = useState<Record<string, unknown>[]>([]);
  // multi-factor sign-in
  const [mfaTicket, setMfaTicket] = useState('');
  const [nextFactor, setNextFactor] = useState('');
  const [code, setCode] = useState('');
  const [challengeData, setChallengeData] = useState('');
  // enrolment
  const [factors, setFactors] = useState<Factor[]>([]);
  const [offered, setOffered] = useState<string[]>([]);
  const [enrollingType, setEnrollingType] = useState('');
  const [enrollDisplay, setEnrollDisplay] = useState('');
  // Enrolling a factor rewrites what it takes to sign in, so the server demands a fresh step-up
  // (P18 poz. 2): a merely-live — possibly stolen — session must not be able to add a factor the
  // thief holds. The FIRST factor is proven with the password; a later one with the factors already
  // enrolled, which is why this carries both a password and a ticket.
  const [enrolStepUpType, setEnrolStepUpType] = useState('');
  const [enrolStepUpPassword, setEnrolStepUpPassword] = useState('');
  const [enrolStepUpTicket, setEnrolStepUpTicket] = useState('');
  const [enrolStepUpCode, setEnrolStepUpCode] = useState('');
  const [enrollTarget, setEnrollTarget] = useState('');
  const [enrolCode, setEnrolCode] = useState('');
  // recovery codes: shown exactly once, right after generation; only the count is retrievable later
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [recoveryUnused, setRecoveryUnused] = useState<number | null>(null);
  // password reset: the token arrives in the link (?reset=...), the new password in the form
  const [resetToken, setResetToken] = useState('');
  // password change (signed in): prove the current one, pick the next
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  // e-mail change (signed in): the confirmation link goes to the NEW address
  const [newEmail, setNewEmail] = useState('');
  // every active session of the account (family id + refresh expiry)
  const [sessions, setSessions] = useState<Session[]>([]);
  // account deletion: irreversible, so it demands a fresh step-up (password, then factors)
  const [deleting, setDeleting] = useState(false);
  const [deletePassword, setDeletePassword] = useState('');
  const [deleteTicket, setDeleteTicket] = useState('');
  const [deleteCode, setDeleteCode] = useState('');

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const mailed = params.get('verify');
    const reset = params.get('reset');
    const change = params.get('change');
    if (!mailed && !reset && !change) return;
    history.replaceState(null, '', location.pathname);
    if (reset) {
      // the link only carries the token; the new password is typed on the reset screen
      setResetToken(reset);
      setMode('reset');
      return;
    }
    if (change) {
      void fetch(`${SECURITY}/confirm-email-change`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: change }),
      }).then((r) =>
        setNotice(r.ok
          ? 'E-mail changed — sign in with your new address.'
          : 'This change link was already used or has expired.'),
      );
      return;
    }
    void fetch(`${SECURITY}/verify-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: mailed }),
    }).then((r) =>
      setNotice(r.ok
        ? 'E-mail verified — sign in below.'
        : 'This verification link was already used or replaced by a newer one.'),
    );
  }, []);

  const reset = () => {
    setNotice(null);
    setEmailErrors([]);
    setPasswordErrors([]);
  };

  const switchTo = (next: Mode) => {
    setMode(next);
    reset();
  };

  const enterSession = async (accessToken: string) => {
    const meResponse = await request(`${SECURITY}/me`, { headers: { Authorization: `Bearer ${accessToken}` } });
    const meBody: { email: string; roles?: string[]; mfaCompliant?: boolean; requiredFactors?: number; haveFactors?: number } =
      await meResponse.json();
    setToken(accessToken);
    setMe(meBody.email);
    setRoles(meBody.roles ?? []);
    setCompliant(meBody.mfaCompliant ?? true);
    setFloor({ required: meBody.requiredFactors ?? 1, have: meBody.haveFactors ?? 1 });
    setMode('me');
    void loadFactors(accessToken);
    void loadSessions(accessToken);
  };

  const loadSessions = async (accessToken: string) => {
    const r = await request(`${SECURITY}/sessions`, { headers: { Authorization: `Bearer ${accessToken}` } });
    if (r.ok) setSessions((await r.json()).sessions ?? []);
  };

  const revokeAllSessions = async () => {
    reset();
    const r = await request(`${SECURITY}/sessions/revoke-all`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (r.ok) {
      // our own session died with the rest — back to the door
      signOut();
      setNotice('Signed out everywhere.');
    } else {
      setNotice(`Could not revoke the sessions (${r.status}).`);
    }
  };

  const signIn = async () => {
    reset();
    try {
      const r = await request(`${SECURITY}/authenticate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      if (r.status === 202) {
        // more factors owed — the first challenge is out; ask for the proof.
        // (202 is "ok" to fetch, so this MUST be checked before r.ok)
        const body = await bodyOf<{ mfaTicket: string; nextFactor: string; challengeData?: string }>(r);
        setMfaTicket(body.mfaTicket ?? '');
        setNextFactor(body.nextFactor ?? '');
        setChallengeData(body.challengeData ?? '');
        setCode('');
        setMode('mfa');
        return;
      }
      if (r.ok) {
        await enterSession((await bodyOf<{ accessToken: string }>(r)).accessToken ?? '');
        return;
      }
      // Only these three statuses are answers about the CREDENTIALS. Everything else — 500, a
      // proxy's 502, a 504 while the database is down — used to land on "Wrong e-mail or
      // password." and send people off to reset a password that was perfectly correct.
      throw new HttpError(r.status);
    } catch (failure) {
      setNotice(messageFor(failure, {
        401: 'Wrong e-mail or password.',
        403: 'E-mail not verified yet — follow the link in the mail first.',
        429: 'Too many failed attempts — this source is blocked for a while.',
      }));
    }
  };

  const submitFactor = async (proof: string) => {
    reset();
    try {
      const r = await request(`${SECURITY}/authenticate/factor`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaTicket, proof }),
      });
      if (r.status === 202) {
        // the chain has another link — 202 is "ok" to fetch, so check it before r.ok
        const body = await bodyOf<{ nextFactor: string; challengeData?: string }>(r);
        setNextFactor(body.nextFactor ?? '');
        setChallengeData(body.challengeData ?? '');
        setCode('');
        return;
      }
      if (r.ok) {
        await enterSession((await bodyOf<{ accessToken: string }>(r)).accessToken ?? '');
        return;
      }
      // bodyOf, not r.json(): this branch used to parse unconditionally, so a 502 carrying HTML
      // threw inside the handler and the screen kept the spinner with nothing said
      const body = await bodyOf<{ status?: string; attemptsLeft?: number }>(r);
      if (body.status === 'WRONG_CODE') {
        setNotice(`Wrong code${body.attemptsLeft != null ? ` — ${body.attemptsLeft} tries left` : ''}.`);
        return;
      }
      if (r.status >= 500) {
        throw new HttpError(r.status);   // not the user's doing; do not send them back to the start
      }
      setNotice('That sign-in expired — start over.');
      switchTo('signin');
    } catch (failure) {
      setNotice(messageFor(failure, {}));
    }
  };

  // a passkey step needs no typing: sign the challenge and submit the assertion
  const submitPasskey = async () => {
    reset();
    try {
      const assertion = await assertPasskey(challengeData);
      if (assertion) await submitFactor(assertion);
    } catch {
      setNotice('Passkey sign-in was cancelled or failed.');
    }
  };

  // when the sign-in chain reaches a passkey, prompt the authenticator right away
  useEffect(() => {
    if (mode === 'mfa' && nextFactor === 'WEBAUTHN' && challengeData) {
      void submitPasskey();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, nextFactor, challengeData]);

  const signUp = async () => {
    reset();
    const r = await request(`${SECURITY}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    if (r.status === 201) {
      setMode('inbox');
    } else if (r.status === 422) {
      // both channels answer in one shape: {CODE: the parameter in force} or {CODE: true}
      const errors: { emailErrors?: Record<string, unknown>[]; passwordErrors?: Record<string, unknown>[] } = await r.json();
      setEmailErrors(errors.emailErrors ?? []);
      setPasswordErrors(errors.passwordErrors ?? []);
    } else {
      setNotice(`Registration failed (${r.status}).`);
    }
  };

  const loadFactors = async (accessToken: string) => {
    const r = await request(`${SECURITY}/account/factors`, { headers: { Authorization: `Bearer ${accessToken}` } });
    if (r.ok) { const body = await r.json(); setFactors(body.have ?? []); setOffered(body.offered ?? []); }
    const rc = await request(`${SECURITY}/account/recovery-codes`, { headers: { Authorization: `Bearer ${accessToken}` } });
    if (rc.ok) setRecoveryUnused((await rc.json()).unused ?? 0);
  };

  /**
   * Not a factor type — the sentinel that reuses the enrolment step-up panel for the ONE other
   * action behind the same door. Generating recovery codes hands out credentials that bypass the
   * whole factor chain, so the server demands a fresh elevation for it exactly as it does for
   * enrolment; the UI simply never learned to ask, and the button answered 403 in silence.
   */
  const RECOVERY_STEP_UP = 'RECOVERY_CODES';

  /**
   * The third action behind the same door. Moving the address MOVES THE ACCOUNT — the confirmation
   * lands in the new mailbox — so a merely-live session must not start it either.
   */
  const CHANGE_EMAIL_STEP_UP = 'CHANGE_EMAIL';

  const generateRecoveryCodes = async () => {
    setNotice(null);
    const r = await request(`${SECURITY}/account/recovery-codes`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (r.ok) {
      const body: { codes: string[] } = await r.json();
      setRecoveryCodes(body.codes ?? []);           // the one and only time they are visible
      setRecoveryUnused((body.codes ?? []).length);
    } else if (r.status === 403) {
      // STEP_UP_REQUIRED, exactly like starting an enrolment: an extra proof to collect, after
      // which this very generation resumes on its own
      setEnrolStepUpType(RECOVERY_STEP_UP);
      setEnrolStepUpPassword('');
      setEnrolStepUpTicket('');
      setEnrolStepUpCode('');
    } else {
      setNotice(`Could not generate recovery codes (${r.status}).`);
    }
  };

  const startEnrol = async (type: string) => {
    setNotice(null);
    const body = type === 'SMS_CODE' ? JSON.stringify({ target: enrollTarget }) : '{}';
    const r = await request(`${SECURITY}/account/factors/${type}/enroll/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body,
    });
    if (r.status === 202) {
      const setup: { status: string; display?: string } = await r.json();
      if (type === 'WEBAUTHN') {
        // a passkey enrols in one gesture: create the credential and confirm the attestation
        await confirmPasskeyEnrol(setup.display ?? '');
        return;
      }
      setEnrollingType(type);
      setEnrollDisplay(setup.display ?? '');
      setEnrolCode('');
    } else if (r.status === 403) {
      // STEP_UP_REQUIRED. Not an error to report — an extra proof to collect, after which this very
      // enrolment resumes on its own.
      setEnrolStepUpType(type);
      setEnrolStepUpPassword('');
      setEnrolStepUpTicket('');
      setEnrolStepUpCode('');
    } else {
      setNotice('Could not start enrolment.');
    }
  };

  /**
   * Which door the elevation is bought for. Since P18 an elevation is keyed by token AND action,
   * so this name decides which endpoint it opens — asking for the wrong one buys an elevation that
   * changes nothing and leaves the caller in a 403 loop.
   */
  const stepUpActionOf = (type: string) => {
    if (type === RECOVERY_STEP_UP) return 'generate-recovery-codes';
    if (type === CHANGE_EMAIL_STEP_UP) return 'change-email';
    return 'enrol-factor';
  };

  /** What the elevation was bought FOR — the request that was interrupted, run again. */
  const resumeAfterStepUp = async (type: string) => {
    if (type === RECOVERY_STEP_UP) return void await generateRecoveryCodes();
    if (type === CHANGE_EMAIL_STEP_UP) return void await requestEmailChange();
    return void await startEnrol(type);
  };

  /** The password half of the enrolment step-up; a second factor may still be asked for after it. */
  const proveForEnrol = async () => {
    const type = enrolStepUpType;
    const r = await request(`${SECURITY}/account/step-up`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      // the action NAMES the door: since P18 an elevation is keyed by token AND action, so asking
      // for 'enrol-factor' would buy an elevation the recovery-codes endpoint does not accept
      body: JSON.stringify({ action: stepUpActionOf(type), password: enrolStepUpPassword }),
    });
    const body: { status?: string; stepUpTicket?: string } = await r.json().catch(() => ({}));
    if (r.status === 200 && body.status === 'ELEVATED') {
      setEnrolStepUpType('');
      await resumeAfterStepUp(type);
    } else if (r.status === 202 && body.status === 'FACTOR_REQUIRED') {
      setEnrolStepUpTicket(body.stepUpTicket ?? '');
    } else if (r.status === 401 || r.status === 403) {
      setNotice('Wrong password.');
    } else {
      setNotice(`Security answered ${r.status}. Please try again.`);
    }
  };

  /** The factor half: the chain the account already carries, one link at a time. */
  const proveFactorForEnrol = async () => {
    const type = enrolStepUpType;
    // Authorization is NOT optional here: AuthorizationFilter guards /account/** and answers 401
    // before the controller ever sees the ticket (the defect P18 poz. 8 fixed on the deletion path).
    const r = await request(`${SECURITY}/account/step-up/factor`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ stepUpTicket: enrolStepUpTicket, proof: enrolStepUpCode }),
    });
    const body: { status?: string; stepUpTicket?: string } = await r.json().catch(() => ({}));
    if (r.status === 200) {
      setEnrolStepUpType('');
      await resumeAfterStepUp(type);
    } else if (r.status === 202 && body.status === 'FACTOR_REQUIRED') {
      setEnrolStepUpTicket(body.stepUpTicket ?? enrolStepUpTicket);
      setEnrolStepUpCode('');
    } else {
      setNotice('Wrong code.');
    }
  };

  const confirmPasskeyEnrol = async (display: string) => {
    try {
      const attestation = await enrolPasskey(display);
      if (!attestation) { setNotice('Passkey enrolment was cancelled.'); return; }
      const r = await request(`${SECURITY}/account/factors/WEBAUTHN/enroll/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ code: attestation }),
      });
      if (r.ok) {
        setNotice('passkey enrolled — you will use it next sign-in.');
        void loadFactors(token);
      } else {
        setNotice('Passkey enrolment not completed.');
      }
    } catch {
      setNotice('Passkey enrolment was cancelled or failed.');
    }
  };

  const confirmEnrol = async () => {
    const r = await request(`${SECURITY}/account/factors/${enrollingType}/enroll/confirm`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ code: enrolCode }),
    });
    if (r.ok) {
      setNotice(`${factorLabel(enrollingType)} enrolled — you will use it next sign-in.`);
      setEnrollingType(''); setEnrollDisplay(''); setEnrollTarget('');
      void loadFactors(token);
    } else {
      setNotice('Wrong code — enrolment not completed.');
    }
  };

  const requestReset = async () => {
    reset();
    const r = await request(`${SECURITY}/reset-password/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    setNotice(r.status === 202
      ? 'If that address has an account, a reset link is on its way.'
      : r.status === 429
        ? 'Too many reset requests — try again later.'
        : `Could not request a reset (${r.status}).`);
  };

  const completeReset = async () => {
    reset();
    const r = await request(`${SECURITY}/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: resetToken, password }),
    });
    if (r.ok) {
      setPassword('');
      switchTo('signin');
      setNotice('Password reset — sign in with your new password.');
    } else {
      const body: { status?: string } = await r.json().catch(() => ({}));
      setNotice(body.status === 'WEAK_PASSWORD'
        ? 'That password is too weak — pick a stronger one.'
        : 'This reset link was already used or has expired.');
    }
  };

  const changePassword = async () => {
    reset();
    const r = await request(`${SECURITY}/account/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ currentPassword, newPassword }),
    });
    if (r.ok) {
      setCurrentPassword('');
      setNewPassword('');
      setNotice('Password changed.');
    } else {
      const body: { status?: string } = await r.json().catch(() => ({}));
      setNotice(body.status === 'WEAK_PASSWORD'
        ? 'That password is too weak — pick a stronger one.'
        : 'Wrong current password.');
    }
  };

  const requestEmailChange = async () => {
    reset();
    const r = await request(`${SECURITY}/account/email/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ newEmail }),
    });
    if (r.status === 403) {
      // STEP_UP_REQUIRED: an extra proof to collect, after which this very request resumes
      setEnrolStepUpType(CHANGE_EMAIL_STEP_UP);
      setEnrolStepUpPassword('');
      setEnrolStepUpTicket('');
      setEnrolStepUpCode('');
      return;
    }
    // 202 whatever the address's fate — the truth goes by mail (anti-enumeration)
    setNotice(r.status === 202
      ? 'Check the new address — we sent a confirmation link.'
      : `Could not request the change (${r.status}).`);
    if (r.status === 202) setNewEmail('');
  };

  const performDelete = async () => {
    try {
      // the address in the path is the caller's own, which is what makes this a request to be
      // forgotten rather than an administrator's act — the same route, a different address
      const r = await request(`${SECURITY}/account/${encodeURIComponent(me)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (r.status === 202) {
        signOut();
        setNotice('Account closing — you are signed out everywhere.');
        return;
      }
      throw new HttpError(r.status);
    } catch (failure) {
      setNotice(messageFor(failure, {}));
    }
  };

  const startDelete = async () => {
    reset();
    try {
      const r = await request(`${SECURITY}/account/step-up`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ action: 'delete-account', password: deletePassword }),
      });
      if (r.status === 202) {
        // the chain has factors — 202 is "ok" to fetch, so check it before r.ok
        setDeleteTicket((await bodyOf<{ stepUpTicket: string }>(r)).stepUpTicket ?? '');
        setDeleteCode('');
        return;
      }
      if (r.ok) {
        await performDelete();
        return;
      }
      // "Wrong password." used to cover every non-2xx here, a dead backend included — a person
      // whose password was right would retype it until they gave up
      throw new HttpError(r.status);
    } catch (failure) {
      setNotice(messageFor(failure, { 401: 'Wrong password.', 403: 'Wrong password.' }));
    }
  };

  const submitDeleteCode = async () => {
    reset();
    try {
      const r = await request(`${SECURITY}/account/step-up/factor`, {
        method: 'POST',
        // Authorization is not optional here: AuthorizationFilter guards /account/** and answers
        // 401 BEFORE the controller — which messageFor below then blamed on the code, so an
        // account with a factor could never delete itself through this UI
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ stepUpTicket: deleteTicket, proof: deleteCode }),
      });
      if (r.status === 202) {
        setDeleteCode('');   // another link in the chain
        return;
      }
      if (r.ok) {
        await performDelete();
        return;
      }
      throw new HttpError(r.status);
    } catch (failure) {
      setNotice(messageFor(failure, { 401: 'Wrong code.', 403: 'Wrong code.' }));
    }
  };

  const signOut = () => {
    // end the session server-side too — with a same-origin deployment the refresh cookie rides
    // along and the session family dies; cross-origin (no cookie) it is an idempotent no-op
    void fetch(`${SECURITY}/logout`, { method: 'POST', credentials: 'include', keepalive: true })
      .catch(() => { /* signing out locally must never hang on the network */ });
    setToken('');
    setMe('');
    setRoles([]);
    setFactors([]);
    switchTo('signin');
  };

  return (
    <div className="card">
      {mode === 'me' && (
        <AccountScreen
          identity={{ me, roles, compliant, floor }}
          factors={{
            have: factors, offered,
            enrollingType, enrollDisplay, enrollTarget, enrolCode,
            setEnrollTarget, setEnrolCode,
            startEnrol: (type) => void startEnrol(type),
            confirmEnrol: () => void confirmEnrol(),
            stepUpType: enrolStepUpType,
            stepUpPassword: enrolStepUpPassword, setStepUpPassword: setEnrolStepUpPassword,
            stepUpTicket: enrolStepUpTicket,
            stepUpCode: enrolStepUpCode, setStepUpCode: setEnrolStepUpCode,
            prove: () => void proveForEnrol(),
            proveFactor: () => void proveFactorForEnrol(),
          }}
          recovery={{
            codes: recoveryCodes, unused: recoveryUnused,
            generate: () => void generateRecoveryCodes(),
          }}
          sessions={{ list: sessions, revokeAll: () => void revokeAllSessions() }}
          emailChange={{ newEmail, setNewEmail, request: () => void requestEmailChange() }}
          passwordChange={{
            currentPassword, newPassword, setCurrentPassword, setNewPassword,
            change: () => void changePassword(),
          }}
          deletion={{
            deleting, password: deletePassword, ticket: deleteTicket, code: deleteCode,
            setDeleting, setPassword: setDeletePassword, setCode: setDeleteCode,
            start: () => void startDelete(),
            submitCode: () => void submitDeleteCode(),
          }}
          onSignOut={signOut}
        />
      )}

      {mode === 'mfa' && (
        <MfaScreen
          nextFactor={nextFactor}
          code={code}
          setCode={setCode}
          submitFactor={(proof) => void submitFactor(proof)}
          submitPasskey={() => void submitPasskey()}
        />
      )}

      {mode === 'forgot' && (
        <ForgotScreen email={email} setEmail={setEmail}
                      requestReset={() => void requestReset()} switchTo={switchTo} />
      )}

      {mode === 'reset' && (
        <ResetScreen password={password} setPassword={setPassword}
                     completeReset={() => void completeReset()} />
      )}

      {mode === 'inbox' && <InboxScreen email={email} switchTo={switchTo} />}

      {(mode === 'signin' || mode === 'signup') && (
        <SignInUpScreen mode={mode} email={email} password={password}
                        setEmail={setEmail} setPassword={setPassword} switchTo={switchTo}
                        signIn={() => void signIn()} signUp={() => void signUp()} />
      )}

      {notice && <p data-testid="notice" className="notice">{notice}</p>}
      {(emailErrors.length > 0 || passwordErrors.length > 0) && (
        <div data-testid="validation-errors" className="notice">
          That will not do:
          <ul data-testid="email-errors">{emailErrors.map(renderFieldError)}</ul>
          <ul data-testid="password-errors">{passwordErrors.map(renderFieldError)}</ul>
        </div>
      )}
    </div>
  );
}
