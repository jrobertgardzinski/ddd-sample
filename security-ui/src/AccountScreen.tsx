import { Factor, Session, factorLabel } from './lib';

/**
 * The signed-in account screen: who you are, your sign-in factors (with enrolment), recovery
 * codes, active sessions, e-mail/password change and the danger zone. Purely presentational —
 * every piece of state and every action arrives from {@link App}, grouped by concern, so this
 * file owns the layout and App owns the behaviour. All data-testids are the e2e suite's contract.
 */
export function AccountScreen(props: {
  identity: { me: string; roles: string[]; compliant: boolean; floor: { required: number; have: number } };
  factors: {
    have: Factor[]; offered: string[];
    enrollingType: string; enrollDisplay: string; enrollTarget: string; enrolCode: string;
    setEnrollTarget: (v: string) => void; setEnrolCode: (v: string) => void;
    startEnrol: (type: string) => void; confirmEnrol: () => void;
    stepUpType: string;
    stepUpPassword: string; setStepUpPassword: (v: string) => void;
    stepUpTicket: string;
    stepUpCode: string; setStepUpCode: (v: string) => void;
    stepUpFactor: string;
    prove: () => void; proveFactor: () => void; provePasskey: () => void;
  };
  recovery: { codes: string[]; unused: number | null; generate: () => void };
  sessions: { list: Session[]; revokeAll: () => void };
  emailChange: { newEmail: string; setNewEmail: (v: string) => void; request: () => void };
  passwordChange: {
    currentPassword: string; newPassword: string;
    setCurrentPassword: (v: string) => void; setNewPassword: (v: string) => void; change: () => void;
  };
  deletion: {
    deleting: boolean; password: string; ticket: string; code: string;
    setDeleting: (v: boolean) => void; setPassword: (v: string) => void; setCode: (v: string) => void;
    start: () => void; submitCode: () => void;
  };
  onSignOut: () => void;
}) {
  const { identity, factors, recovery, sessions, emailChange, passwordChange, deletion, onSignOut } = props;
  return (
    <>
      <h3>Signed in</h3>
      <p>You are <b data-testid="signed-in-email">{identity.me}</b> ({identity.roles.join(', ')}).</p>

      {!identity.compliant && (
        <p data-testid="mfa-required" className="notice">
          Your role needs {identity.floor.required} sign-in factors — you have {identity.floor.have}. Add another
          below to unlock everything.
        </p>
      )}

      <h4>Sign-in factors</h4>
      <ul data-testid="factor-list">
        {factors.have.map((f) => <li key={f.type}>{f.label}</li>)}
        {factors.have.length === 0 && <li><i>password only</i></li>}
      </ul>
      {!factors.enrollingType && factors.offered.filter((t) => !factors.have.some((f) => f.type === t)).map((type) => (
        <div key={type}>
          {type === 'SMS_CODE' && (
            <input data-testid="enroll-phone" placeholder="+48…"
                   value={factors.enrollTarget} onChange={(e) => factors.setEnrollTarget(e.target.value)} />
          )}
          <button data-testid={`add-${type}`} onClick={() => factors.startEnrol(type)}>
            Add {factorLabel(type)}
          </button>
        </div>
      ))}
      {factors.stepUpType && (
        // adding a factor is a change to how this account signs in, so the server asks for proof
        // first — the password while there is nothing else to prove with, a factor once there is
        <div data-testid="enrol-stepup">
          {/* the same door guards two things: adding a factor, and minting recovery codes that
              bypass the whole factor chain — so the wording covers both rather than promising
              an enrolment that may not be happening */}
          <p>Confirm it is you before changing how you sign in:</p>
          {!factors.stepUpTicket ? (
            <>
              <input data-testid="enrol-stepup-password" type="password" placeholder="your password"
                     value={factors.stepUpPassword}
                     onChange={(e) => factors.setStepUpPassword(e.target.value)} />
              <button data-testid="enrol-stepup-submit" onClick={() => factors.prove()}>Continue</button>
            </>
          ) : factors.stepUpFactor === 'WEBAUTHN' ? (
            // a passkey is signed, not typed: the authenticator is prompted as soon as the ticket
            // arrives, and this is the way back if the prompt was dismissed. Rendering the code
            // input here instead is what shut passkey-only accounts out of every guarded action.
            <>
              <p data-testid="enrol-stepup-passkey">Confirm with your passkey to continue.</p>
              <button data-testid="enrol-stepup-passkey-retry"
                      onClick={() => factors.provePasskey()}>Use passkey</button>
            </>
          ) : (
            <>
              <input data-testid="enrol-stepup-code" placeholder="code we sent you"
                     value={factors.stepUpCode}
                     onChange={(e) => factors.setStepUpCode(e.target.value)} />
              <button data-testid="enrol-stepup-code-submit"
                      onClick={() => factors.proveFactor()}>Continue</button>
            </>
          )}
        </div>
      )}
      {factors.enrollingType && (
        <div>
          {factors.enrollDisplay && (
            <p data-testid="enroll-otpauth" style={{ wordBreak: 'break-all', fontSize: '0.8rem' }}>
              Scan this in your authenticator app: <code>{factors.enrollDisplay}</code>
            </p>
          )}
          <input data-testid="enroll-code"
                 placeholder={factors.enrollDisplay ? 'code from your app' : 'code we sent you'}
                 value={factors.enrolCode} onChange={(e) => factors.setEnrolCode(e.target.value)} />
          <button data-testid="enroll-submit" onClick={() => factors.confirmEnrol()}>Confirm</button>
        </div>
      )}
      <h4>Recovery codes</h4>
      {recovery.codes.length > 0 ? (
        <div data-testid="recovery-codes">
          <p className="notice">
            Save these now — they will never be shown again. Each signs you in once when a
            factor is out of reach.
          </p>
          <ul style={{ columns: 2, fontFamily: 'monospace' }}>
            {recovery.codes.map((c) => <li key={c}>{c}</li>)}
          </ul>
        </div>
      ) : (
        <p data-testid="recovery-count">
          {recovery.unused ? `${recovery.unused} unused code(s) left.` : 'None yet.'}{' '}
          <button data-testid="generate-recovery" onClick={() => recovery.generate()}>
            Generate {recovery.unused ? 'a fresh batch (replaces the old one)' : 'recovery codes'}
          </button>
        </p>
      )}
      <h4>Active sessions</h4>
      <ul data-testid="session-list">
        {sessions.list.map((s) => (
          <li key={s.family} data-testid="session-row">
            <code>{s.family.slice(0, 8)}…</code> — until {s.expiresAt}
          </li>
        ))}
      </ul>
      <p><button data-testid="revoke-all" onClick={() => sessions.revokeAll()}>
        Sign out everywhere
      </button></p>

      <h4>Change e-mail</h4>
      <form onSubmit={(e) => { e.preventDefault(); emailChange.request(); }}>
        <input data-testid="new-email" type="text" placeholder="new e-mail" autoComplete="email"
               value={emailChange.newEmail} onChange={(e) => emailChange.setNewEmail(e.target.value)} />
        <button data-testid="change-email-submit" type="submit">Send confirmation link</button>
      </form>

      <h4>Change password</h4>
      <form onSubmit={(e) => { e.preventDefault(); passwordChange.change(); }}>
        <input data-testid="current-password" type="password" placeholder="current password"
               autoComplete="current-password"
               value={passwordChange.currentPassword}
               onChange={(e) => passwordChange.setCurrentPassword(e.target.value)} />
        <input data-testid="new-password" type="password" placeholder="new password"
               autoComplete="new-password"
               value={passwordChange.newPassword}
               onChange={(e) => passwordChange.setNewPassword(e.target.value)} />
        <button data-testid="change-password-submit" type="submit">Change password</button>
      </form>
      <h4>Danger zone</h4>
      {!deletion.deleting ? (
        <p><button data-testid="delete-account" onClick={() => deletion.setDeleting(true)}>
          Delete my account…
        </button></p>
      ) : (
        <div>
          <p className="notice">This cannot be undone — prove it is you.</p>
          <input data-testid="delete-password" type="password" placeholder="your password"
                 autoComplete="current-password"
                 value={deletion.password} onChange={(e) => deletion.setPassword(e.target.value)} />
          <button data-testid="delete-start" onClick={() => deletion.start()}>Continue</button>
          {deletion.ticket && (
            <div>
              <input data-testid="delete-code" placeholder="code we sent you"
                     value={deletion.code} onChange={(e) => deletion.setCode(e.target.value)} />
              <button data-testid="delete-submit" onClick={() => deletion.submitCode()}>
                Confirm deletion
              </button>
            </div>
          )}
        </div>
      )}
      <p><button data-testid="sign-out" onClick={onSignOut}>Sign out</button></p>
    </>
  );
}
