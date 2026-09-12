# OAuth providers — configuration recipes

Social sign-in is **pure configuration**: one entry under
`security.oauth.providers.<name>.*` per provider, and `GET /oauth/providers`
tells the UI which buttons to draw. The configuration type itself is
`OauthProviderSettings` in the **config layer** (`security-config`) — a
framework-free record carrying every knob, its defaults and validation;
the infrastructure layer only binds the properties into it. The dance (Authorization Code + PKCE S256,
single-use state, allow-listed return URL, access token in the fragment) never
changes; what differs between providers is how the identity is asserted once
the code is exchanged — the `identity-source`:

| source     | who                     | how the identity arrives                              |
|------------|-------------------------|-------------------------------------------------------|
| `ID_TOKEN` | Google, GitLab, stub IdP | full OIDC: signed `id_token` from the token endpoint (iss/aud/exp/nonce validated hard) |
| `USERINFO` | GitHub, Facebook         | plain OAuth2: the access token is spent server-side on `GET userinfo-url`; fields mapped by config |

Common keys: `authorize-url` (browser-facing), `token-url` (server-side),
`client-id`, `client-secret`, `redirect-uri`, `scope` (default `openid email`),
`label` (button text, defaults to the capitalised name), and `issuer`.

`issuer` was missing from this list while the code has always checked `iss` against it when it is
set — so a deployment that never heard of the key got no issuer check at all, silently. Since
2026-09-12 it is not optional in practice either: an id_token signed with anything but HS256 is
accepted on the strength of the direct TLS channel to the token endpoint (OIDC Core 3.1.3.7), and
that argument only holds for a provider whose claims can be checked against a declared issuer — so
such a provider without one is refused at the callback rather than trusted for being unverifiable.
The URLs are validated at boot as absolute http(s) URLs; `idp:8091/token` used to boot happily and
answer 500 at the callback.

USERINFO keys: `userinfo-url`, `subject-field` (default `sub`), `email-field`
(default `email`), `email-verified-field` (default `email_verified`),
`emails-url` (optional; GitHub-shaped array of `{email, primary, verified}`,
consulted when userinfo hides the address or the verified flag),
`assume-email-verified` (default `false` — see the warning below).

## Google (ID_TOKEN) — live today

```yaml
security.oauth.providers.google:
  issuer: https://accounts.google.com
  authorize-url: https://accounts.google.com/o/oauth2/v2/auth
  token-url: https://oauth2.googleapis.com/token
  client-id: <from Google Cloud Console>
  client-secret: <from Google Cloud Console>
  redirect-uri: https://<your-host>/oauth/callback
```

The RS256 signature is accepted on the strength of the direct TLS channel to
the token endpoint (OIDC Core 3.1.3.7); iss/aud/exp/nonce are still checked hard.
In the compose stack the same provider name points at the stub IdP (HS256,
verified against the client secret).

## GitLab (ID_TOKEN)

GitLab is a compliant OIDC provider — same shape as Google:

```yaml
security.oauth.providers.gitlab:
  issuer: https://gitlab.com
  authorize-url: https://gitlab.com/oauth/authorize
  token-url: https://gitlab.com/oauth/token
  scope: openid email
  client-id: <application id>
  client-secret: <application secret>
  redirect-uri: https://<your-host>/oauth/callback
  label: GitLab
```

## GitHub (USERINFO + emails-url)

GitHub speaks no OIDC: no id_token, numeric `id`, and the e-mail is often
private (null in `/user`) — the truth lives behind `/user/emails`, which also
carries the real `verified` flag:

```yaml
security.oauth.providers.github:
  identity-source: USERINFO
  authorize-url: https://github.com/login/oauth/authorize
  token-url: https://github.com/login/oauth/access_token
  userinfo-url: https://api.github.com/user
  emails-url: https://api.github.com/user/emails
  scope: read:user user:email
  subject-field: id
  client-id: <OAuth app client id>
  client-secret: <OAuth app client secret>
  redirect-uri: https://<your-host>/oauth/callback
  label: GitHub
```

The primary verified address wins; an unverified-only account never signs in.

## Facebook (USERINFO + assume-email-verified)

Facebook's Graph API returns an e-mail but **never states whether it is
verified**. Accepting it is therefore a per-deployment decision, made explicit:

```yaml
security.oauth.providers.facebook:
  identity-source: USERINFO
  authorize-url: https://www.facebook.com/v19.0/dialog/oauth
  token-url: https://graph.facebook.com/v19.0/oauth/access_token
  userinfo-url: https://graph.facebook.com/v19.0/me?fields=id,email
  scope: email
  subject-field: id
  assume-email-verified: true   # ⚠ deliberate: Facebook vouches for nothing
  client-id: <app id>
  client-secret: <app secret>
  redirect-uri: https://<your-host>/oauth/callback
  label: Facebook
```

⚠ **`assume-email-verified` links provider identities to local accounts on an
address nobody vouched for.** Without it (the default) a provider that states
no verification bounces back with `EMAIL_NOT_VOUCHED` and no session — the
safe refusal. Turn it on only when you accept that a Facebook account whose
e-mail was never confirmed could reach the matching local account.

## The compose stack

Both flavours run against the same stub IdP (`microservice-idp`): `google`
exercises ID_TOKEN, `github` exercises USERINFO (`/userinfo` on the stub).
`infra-smoke.sh` proves both paths live.

## Email change & federated identities

A confirmed email change **re-points every federated link** to the new address
(`ConfirmEmailChange` → `FederatedIdentityRepository.relinkAll`): the link is
keyed by the provider's durable `subject` — the same person, the same Google
account — so it follows the account. (The earlier design severed the links and
relied on auto-relink at the next sign-in; that was an illusion — the provider
keeps reporting its own old address, so the auto-link would never find the
moved account, and could even find a stranger who registered the freed one.)
On account **deletion** the links are severed for good (`unlinkAll`), so no
stale identity can open whatever account later claims the freed address.
Pinned by the "FEDERATED LINKS follow the account" rule in
`specs/change-email.feature`, `ConfirmEmailChangeTest` and `DeleteAccountTest`.

## Keycloak (a real, self-hosted OIDC provider) — recipe

Verified live against Keycloak 26 (2026-07-07): the full dance — authorize,
login form, code, PKCE exchange, session, `/me` — passed headlessly with the
provider configured by env alone; the dance code is identical to Google's.
(The compose stack does not carry a Keycloak container — the proof is banked;
spin one up with `start-dev --import-realm` when you want the button back.)
Keycloak side: a confidential client with the `/oauth/callback` redirect URI,
and a user with a VERIFIED email (and first/last name, or the login form
detours into update-profile). Security side:

```yaml
SECURITY_OAUTH_PROVIDERS_KEYCLOAK_ISSUER:        http://localhost:8180/realms/portfolio
SECURITY_OAUTH_PROVIDERS_KEYCLOAK_AUTHORIZE_URL: http://localhost:8180/realms/portfolio/protocol/openid-connect/auth
SECURITY_OAUTH_PROVIDERS_KEYCLOAK_TOKEN_URL:     http://keycloak:8080/realms/portfolio/protocol/openid-connect/token
SECURITY_OAUTH_PROVIDERS_KEYCLOAK_CLIENT_ID:     security-portfolio
SECURITY_OAUTH_PROVIDERS_KEYCLOAK_CLIENT_SECRET: portfolio-secret
SECURITY_OAUTH_PROVIDERS_KEYCLOAK_REDIRECT_URI:  http://localhost:8080/oauth/callback
SECURITY_OAUTH_PROVIDERS_KEYCLOAK_LABEL:         Keycloak
```

Two Keycloak-specific gotchas, both handled:

- **Issuer vs channels.** The browser visits `localhost:8180`, security
  exchanges the code at `keycloak:8080` — but the id_token carries ONE `iss`.
  `KC_HOSTNAME` pins it to the browser-visible URL, so it matches the
  configured `issuer` regardless of which channel a request used.
- **`aud` may be an array.** Keycloak can mint `aud` as an array (e.g. with
  `account` beside the client). The validator accepts a string equal to our
  client id, or an array containing it with `azp` naming us (OIDC Core
  3.1.3.7); anything else is refused. Pinned in `OauthFlowHttpTest`.
