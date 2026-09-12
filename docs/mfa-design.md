# MFA — design plan

- Status: Accepted (the four open decisions were settled 2026-07-05 — see the end)
- Date: 2026-07-05
- Scope: `microservice-security` (domain / system / config / infrastructure), the React
  `security-ui`, and the compose smoke test. Channel services (`microservice-email`,
  `microservice-sms`) are reused, not rebuilt.

## What this must deliver

1. **MFA as a sequential chain of factors.** Authentication is no longer "verify credentials →
   session". It is "pass factor #1, then #2, then #3 … → session". The session is minted only
   after the last enrolled factor. (User: the factors go one after another, e.g.
   credentials → e-mail code → SMS code — not in parallel.)
2. **Plug-and-play factor methods.** Adding a new method (TOTP / Google Authenticator, WebAuthn
   passkeys, a hardware token, …) must be *a new adapter bean plus an enrollment*, touching no
   core code. E-mail and SMS are just two adapters among many.
3. **Role-driven minimum.** A plain USER may run on one factor (password). Anyone holding a role
   above USER must have a configured minimum — MODERATOR ≥ 2 factors, ADMIN ≥ 3 (deployment-
   configurable). The system *enforces* this: it will not let a privileged account operate under-
   protected, and it will not let a user drop below their role's floor.

Two orthogonal configuration axes, exactly as agreed:
- **Deployment** — which factor types the service *offers* (which adapters are enabled).
- **Per-user** — which factors a user has *enrolled*, and in what order.

## The core abstraction — a factor is a plug

Everything hangs off one port. A factor knows three things about itself and does two things.

```
FactorType            a stable string id ("PASSWORD", "EMAIL_CODE", "SMS_CODE", "TOTP", "WEBAUTHN",
                      "RECOVERY_CODE"). A string, not a domain enum, so a new adapter never edits
                      a central enum — that is the plug-and-play seam.

interface AuthenticationFactor {                       // the PLUG (system/mfa)
    FactorType type();
    boolean needsChallenge();                          // email/sms: yes; TOTP/password/webauthn: no
    Challenge issueChallenge(EnrolledFactor enrolment); // send the code / mint a nonce; no-op if !needsChallenge
    boolean verify(EnrolledFactor enrolment, Challenge challenge, Proof proof);
}

interface FactorEnrolment {                            // the plug for REGISTERING a factor
    FactorType type();
    EnrolmentStart begin(User user, EnrolmentRequest req);   // TOTP → secret+otpauth URI; email → send code; …
    EnrolledFactor confirm(User user, EnrolmentStart start, Proof proof);  // one proof seals it
}
```

- `Challenge` is a value object carrying *only what the boundary needs to remember* between issue
  and verify: an opaque handle plus the hashed secret / nonce, a TTL, single-use. Never the raw
  code. (Same discipline as verification/reset tokens: hashed, TTL, one-shot, throttled.)
- **The code lifecycle lives in the config layer**, like everything tunable here (`BruteForceConfig`,
  the `SourceThrottle` windows): a `ChallengeCodeConfig` (in `security-config`) holds the code TTL,
  the max wrong proofs per ticket, and the code length — all overridable per deployment
  (`security.mfa.code.*`), with sane defaults baked into the config VO (proposed: TTL 5 min,
  5 attempts, 6 digits — defaults, not constants). No magic numbers in the domain or the boundary.
- Challenge-response factors (e-mail, SMS) send something and then check it. Possession factors
  (TOTP, WebAuthn) issue nothing outbound — TOTP verifies the current time-window code against the
  shared secret; WebAuthn signs a nonce. Password is the degenerate case: `needsChallenge=false`,
  `verify` is the existing Argon2 check. Modelling password *as a factor* keeps the chain uniform.

**FactorRegistry** = `Map<FactorType, AuthenticationFactor>` assembled from the enabled adapter
beans. "Which factors does this deployment offer" is "which adapters are on the classpath and
enabled by config" — nothing more. Dropping in Google Authenticator is: write `TotpFactor`
(a ~50-line adapter over a TOTP lib or hand-rolled HMAC-SHA1), register it, done.

### Where each adapter lives

- `PasswordFactor`, `TotpFactor` — pure, self-contained, in `system/mfa` (no external I/O; TOTP is
  just HMAC over a counter). Testable without any stack.
- `EmailCodeFactor`, `SmsCodeFactor` — issue a code through a **`CodeChannel` port** (send a short
  code to an address/number). Adapters: e-mail rides the existing outbox→Kafka→microservice-email
  (a new mail type `AUTH_CODE`); SMS rides microservice-sms's `/send`. The code lifecycle (hash,
  TTL, one-shot, throttle) is shared, not reimplemented per channel.
- `WebAuthnFactor`, `RecoveryCodeFactor` — later, same shape.

## The chain executor — a resumable state machine

A sign-in that needs more than one factor cannot complete in a single request, so the server holds
the half-finished authentication (exactly like the OAuth `OauthFlowStore`): a short-lived,
single-use **MFA ticket**.

```
PendingAuthentication {
    user, remainingFactors (ordered), passedFactors, currentChallenge, expiresAt
}
PendingAuthenticationStore   // in memory, TTL ~5 min, keyed by an opaque ticket
```

Flow over HTTP:

1. `POST /authenticate {email, password}` → password (factor #1) verified. If the user has no
   further enrolled factors → mint `SessionTokens` as today (unchanged happy path for plain USERs).
   Otherwise → **202** `{ mfaTicket, next: { type, needsChallenge } }`; if the next factor needs a
   challenge, it has already been issued (the code is on its way).
2. `POST /authenticate/factor { mfaTicket, proof }` → verify the current factor. Advance:
   - more factors remain → issue the next challenge, return the next `{type}`;
   - none remain → mint `SessionTokens`, return the session (access token + refresh cookie).
3. The ticket is one-shot and TTL-bounded; a wrong proof consumes an attempt (throttled per source
   via the existing `SourceThrottle`, and folded into brute-force accounting so guessing a code is
   as costly as guessing a password).

**Ordering**: link #1 is always password *or* an OAuth provider callback (see composition below).
The tail order comes from the user's enrolment order (they pick it; a sensible default is
"strongest first" — TOTP/WebAuthn before channel codes).

Internally this generalises the current `Authentication` use case: `_VerifyCredentials` becomes
"verify factor #1"; a new `_AdvanceChain` drives the rest; `_GenerateSession` stays exactly where
it is — reached only when the chain is empty. The brute-force guard and the verified-email gate are
unchanged and still run before factor #1.

## The role-driven minimum — the enforcing part

```
MfaPolicy (config)   requiredFactorCount(Set<Role>) = max over the roles, from
                     security.mfa.min-factors-by-role  (USER:1, MODERATOR:2, ADMIN:3 by default;
                     "factor" counts the WHOLE chain incl. the first, so 2FA = password + 1 more).
```

Enforced at three moments — this is what makes it a guarantee, not a suggestion:

1. **At sign-in (the gate).** After the user passes the factors they *have*, compare their enrolled
   count to `requiredFactorCount(theirRoles)`. If short, do **not** mint a full session — mint an
   **enrolment-scoped session**: a session flagged `enrolment_only` that `AuthorizationFilter` lets
   through to `/account/factors/**` and `/me` and nothing else. The user is forced to enrol up to
   their floor before they can do anything privileged. (A React screen walks them through it.)
2. **At role grant.** `SetUserRoles` granting e.g. MODERATOR to a password-only account succeeds
   (an admin should not be blocked on the target's device), but the target is now under-enrolled →
   caught by moment 1 on their next sign-in. `/me` also reports `mfaCompliant: false` so consumers
   and the UI can nudge. (Alternative — refuse the grant until enrolled — rejected: it strands the
   admin on the user's action.)
3. **At factor removal.** `DELETE /account/factors/{type}` is refused (409 `WOULD_BREAK_MFA_FLOOR`)
   if it would drop the user below their role's minimum. You can swap a factor (enrol the new,
   then drop the old), never fall through the floor.

**Bootstrap admin grace.** The first admin (`security.bootstrap-admins`) has no pre-enrolled
factors and cannot be blocked out of the box, or nobody can ever configure anything. A bootstrap
admin is exempt from the gate **only until they enrol once**, and the UI pushes enrolment hard on
first sign-in. (Documented loudly; it is the one deliberate hole and it self-closes.)

## Enrolment

- `GET  /account/factors` → what I have (type + label + order), what this deployment offers, and
  `required` / `have` / `compliant` for my roles.
- `POST /account/factors/{type}/enroll/start` → begins: TOTP returns the secret + an `otpauth://`
  URI (the UI renders a QR); e-mail/SMS send a code to the (given, then to-be-proven) address.
- `POST /account/factors/{type}/enroll/confirm { proof }` → one correct proof seals the enrolment.
- `DELETE /account/factors/{type}` → remove (subject to the floor above).

Enrolling itself is a sensitive action → it should sit behind **step-up** (below), so a stolen live
session cannot quietly add an attacker-controlled factor.

## Recovery & lockout

Losing your phone must not brick the account. **Recovery codes are just another factor**
(`RecoveryCodeFactor`): a set of one-time codes minted at enrolment, shown once, stored hashed;
presenting one satisfies a possession factor in the chain. Optionally an ADMIN can reset another
user's factors — itself a privileged, step-up-gated action, and a good audit-log candidate.

## Step-up — the same executor, reused

Step-up for a sensitive action (delete account, enrol/remove a factor, generate recovery codes,
change e-mail, admin reset, admin roles, admin settings) is *the chain executor run again* against
the live session, producing a short-lived, **one-shot elevation**.

> **As built (2026-09-12):** the elevation is NOT a column on the session row, as this design
> sketched. It is a separate `SessionElevation` port keyed by (access token, action) with its own
> TTL (`security.step-up.ttl-minutes`, default 5), held in memory and cleared the first time it is
> consumed — so a restart means stepping up again, and an elevation bought for one action does not
> open another. The paths are `POST /account/step-up` and `POST /account/step-up/factor`; there is
> no `/start`.

Policy per action, in config:

```
security.step-up.<action> = NONE | SECOND_FACTORS | FULL_CHAIN
   delete-account   → FULL_CHAIN     (re-pass everything incl. password/OAuth — defends a stolen session)
   enrol/remove factor, admin-reset → SECOND_FACTORS (or FULL_CHAIN for admin-reset)
```

Change-password is NOT in the catalogue (it was taken out with the `StepUpAction` enum): the
endpoint verifies the current password inline, which is the same proof the step-up would ask for
first. That inline check is an Argon2 answering "was this guess right", so it carries a per-source
window of its own instead (`security.change-password.max-per-window`) — see
`ChangePasswordThrottleHttpTest`.

`POST /account/step-up` (+ `/factor`) drives it; the endpoint for the sensitive action then
requires a fresh elevation for THAT action or answers `403 STEP_UP_REQUIRED` with what remains.
Federated users step up by re-authenticating at the provider (`prompt=login`) plus their tail —
designed, not built: the code asks for the password or the factors, and never sends anyone back to
the provider.

## OAuth composition

The provider callback is simply **link #1 instead of the password** — the same chain runs after it.
We deliberately do **not** infer additional assurance from `amr`/`acr` claims — Google reports them
poorly.

**Decision 3 (settled): a federated privileged account is held to the FULL floor, and OAuth does
NOT count toward it.** A provider login proves link #1 to *start* a session, but it does not buy a
factor slot — a compromised Google account must not, by itself, satisfy part of an admin's MFA. So
where a password ADMIN needs `password + 2` (password counts, decision 1), a **Google** ADMIN needs
**3 enrolled factors on top of the OAuth login**. Concretely: the sign-in gate compares
`enrolledFactors.count` (excluding the OAuth link) against `requiredFactorCount(roles)` for
federated accounts, versus `enrolledFactors.count` *including* the password for password accounts.
The asymmetry is intentional — the "free" provider link is never one of your factors.

## Storage

- `V11 enrolled_factors(user_email, type, label, factor_order, secret_material, enrolled_at)` —
  `secret_material` is factor-specific and protected per factor: TOTP secret **encrypted at rest**
  (new `security.mfa.secret-key`), recovery codes **hashed**, phone/e-mail stored as the address.
  In-memory adapter for the no-datasource test profile, as everywhere.
- `V12 mfa_recovery_codes` only if recovery codes want their own table rather than rows in
  `enrolled_factors`.
- ~~The `sessions` row gains `enrolment_only` and a one-shot `elevated_until` (step-up).~~ Not as
  built: the elevation lives in its own in-memory store keyed by (access token, action) — see the
  step-up section above.

## Endpoints (summary)

```
POST /authenticate                       → 200 session | 202 {mfaTicket, next}
POST /authenticate/factor {ticket,proof} → advance | 200 session
GET  /account/factors                    → have / offered / required / compliant
POST /account/factors/{type}/enroll/start
POST /account/factors/{type}/enroll/confirm {proof}
DELETE /account/factors/{type}           → 409 WOULD_BREAK_MFA_FLOOR if under floor
POST /account/step-up {action, password?}  → 200 ELEVATED | 202 FACTOR_REQUIRED {stepUpTicket, nextFactor, challengeData}
POST /account/step-up/factor {stepUpTicket, proof}
```

## Phased implementation order

**Status (2026-07-05): phases A, B, C, E, F and D's admin-reset are DONE and tested/live-smoked.**
Deferred with reason: **recovery codes** — they do NOT fit the sequential chain as a *mandatory*
link (you would type one every sign-in). They are an *alternative* factor: "use a recovery code
INSTEAD of a link you cannot reach." That needs the executor to accept an alternative proof for the
current step (a small, separate design change), not a chain link — so it is deliberately not
bolted on. **G** (MFA scenarios in the security-ui e2e) is optional polish: MFA is already proven
by MfaHttpTest / StepUpHttpTest / MfaRoleFloorHttpTest / AdminFactorResetHttpTest and the live smoke. One deliberate
deviation in C: the sign-in gate is a LIVE compliance check in the authorization filter rather than
a persisted `enrolment_only` flag on the session — simpler (no session-schema change) and more
correct (compliance updates the instant a factor is enrolled, without re-login).

Each phase is a green, self-contained slice (build + tests pass), à la the rest of the portfolio.

- **A — the spine + the first factor (E-MAIL CODE, decision 4).** `AuthenticationFactor` port +
  `FactorRegistry` + `PendingAuthentication` chain executor + `PasswordFactor` (wrapping today's
  check, chain of one = unchanged behaviour) + the `CodeChannel` port + **`EmailCodeFactor`** as the
  first real second factor (rides the existing outbox→Kafka→microservice-email, new mail type
  `AUTH_CODE`; a capturing code notifier for in-process tests + Mailpit for the live smoke, exactly
  like verification codes today). Enrol e-mail, sign in password→e-mail-code. Feature + HTTP test +
  a UI enrol/sign-in screen. `mfa.feature`, `V11`. The shared code lifecycle (hash / TTL / one-shot
  / `SourceThrottle`) lands here since e-mail is challenge-response.
- **B — more factors.** `SmsCodeFactor` (microservice-sms, same `CodeChannel` shape) and
  **`TotpFactor`** (self-contained HMAC, no channel — proves the registry really is plug-and-play by
  adding a possession factor with no outbound I/O). This is where "Google Authenticator" lands.
- **C — the role floor.** `MfaPolicy` + the three enforcement moments (sign-in enrolment-gate,
  grant-time `mfaCompliant` on `/me`, removal floor) + bootstrap grace. This is the headline of the
  user's ask.
- **D — recovery + admin reset.** `RecoveryCodeFactor`, admin factor reset (audited, step-up).
- **E — step-up.** Session `elevated` marker + per-action policy; wire delete-account &
  enrol/remove (change-password is guarded by its inline password check and a per-source window,
  not by the step-up).
- **F — OAuth composition.** Provider callback as link #1; `provider-satisfies`; federated floor.
- **G — UI polish + specs.** React enrolment manager + multi-step sign-in; e2e over the new specs
  as the third entry point; compose smoke walks a password→TOTP sign-in and a role-floor gate.

## Phase H — WebAuthn / passkeys (added 2026-07-07): what the port survived

The flagship test of the plug-and-play claim: a factor of a genuinely different *shape* — a
signature, not a code — added with **no library and no schema change**, and the chain executor
untouched. Two things the earlier port did NOT anticipate had to give, and both gave *additively*
(every existing factor kept working, unchanged):

1. **The secret arrives with the confirming proof, not at enrolment start.** Code/TOTP factors
   know their secret at `beginEnrolment` (a target, a generated seed). A passkey's real secret is
   the *public key the browser generates* — it only exists in the confirming attestation. So the
   port gained a default `enrolledMaterial(pendingMaterial, proof)` (identity for everyone else;
   WebAuthn distils `{credentialId, publicKey}` from the proof after `verify` passes), and
   `EnrolFactor.confirm` stores that instead of the pending material.
2. **The sign-in leg must hand the client something to sign.** Code factors send their challenge
   out of band (mail/SMS); nothing crosses the 202. A passkey needs the *nonce* in the response.
   So `Challenge` gained a nullable `publicData` (null for code factors, a base64url nonce for
   WebAuthn) surfaced as `challengeData` on all four MFA 202 shapes — a deliberate, additive wire
   change. Verification still runs against `codeHash`; `publicData` is only the outbound hint.

Everything else is the factor itself, pure JDK: the browser hands over the credential's **SPKI**
public key directly (`AuthenticatorAttestationResponse.getPublicKey()`), so there is **no CBOR/COSE
to parse**; an assertion is an ordinary `SHA256withECDSA` signature over
`authenticatorData || SHA256(clientDataJSON)`. The credential JSON lives in
`EnrolledFactor.secretMaterial` — **no migration**. Config under `security.webauthn.*` (rp-id,
rp-name, allow-listed origins, challenge TTL). Verified at every layer: `WebauthnFactorTest`
(a P-256 keypair plays the browser; enrolment stores the key, a real assertion passes, a tampered
one and a foreign origin are refused), `MfaHttpTest` (the whole enrol→sign-in over the wire, a
tampered assertion refused), and `mfa-passkey.feature` e2e through Chromium's virtual authenticator.
A gotcha worth remembering: a Micronaut `@Value` default containing URL colons is parsed as nested
defaults — wrap it in backticks (the codebase's own convention).

## Decisions (settled 2026-07-05)

1. **Factor counting → total chain incl. the first.** 2FA = password + 1, 3FA = password + 2.
   `min-factors-by-role` counts the whole chain.
2. **Under-enrolled privileged sign-in → enrolment-scoped session.** Sign in, but boxed to
   `/account/factors` + `/me` until the floor is met. (Not a hard refusal — the user gets a path to
   compliance.)
3. **Federated (passwordless) accounts → held to the FULL floor; OAuth does NOT count.** A Google
   ADMIN needs the full factor count *on top of* the provider login (see OAuth composition above).
   The provider link starts a session but is never one of your factors.
4. **First factor → E-MAIL CODE (phase A), TOTP in phase B.** E-mail exercises the challenge-
   response path and the code lifecycle against real infra the portfolio already runs; TOTP follows
   as the proof that a no-I/O possession factor plugs in with zero core change.
