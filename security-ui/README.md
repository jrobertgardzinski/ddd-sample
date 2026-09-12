# security-ui

The auth service's own face — and, more importantly, **the specs' third entry point.**

The feature files live in the neutral top-level `specs/` directory precisely so more than one
runner can drive them. Two already do (the application-level Cucumber glue and the HTTP-level glue,
both JVM). This module adds a third: **cucumber-js + Playwright** driving the *same Gherkin*
through a real React UI in a real browser — same behaviour, a third entry point. Fifteen of the
nineteen features carry `@ui`, and the browser suite is 39 scenarios; the rest are wire-level
(see the tags below).

## The app

A deliberately plain React app (Vite + TS, the same stack as the meme gallery): sign in — single-
or multi-factor, including passkeys — create an account, the "check your mailbox" screen,
confirming a mailed verification link (`?verify=<token>`), a password reset (`?reset=`), an e-mail
change (`?change=`), and an account screen: factors, recovery codes, sessions, password change,
address change and deletion, each with the step-up the server demands. Every element a scenario
touches carries a `data-testid`, so the glue speaks the UI's language, not the DOM's.

There is also a small vitest suite next to the source (`npm test`) for the parts a browser
scenario cannot reach — what one user leaves behind in a tab for the next one, and how a refusal
the UI has not understood is rendered. It runs in CI; the Playwright suite does not (it needs the
whole stack).

```bash
npm install
npm start          # vite on :4200, talks to the stack's security at :8080
npm run build
```

## The e2e run

```bash
npm run e2e:full   # or ./run-e2e.sh
```

`run-e2e.sh` starts security in the **`test` environment** (in-memory stores, a steerable clock,
a captured mailbox — the same environment the JVM tests use) on port **8180**, starts the Vite
dev server, and runs cucumber-js over `../specs/*.feature`. The glue reaches the two backdoors the
`test` environment exposes over HTTP — `/test/clock` (advance time to expire brute-force blocks)
and `/test/mailbox` (read the token a registration "mailed") — the out-of-process twins of what
the in-process JVM glue reads from beans. `npm run e2e` alone assumes both servers are already up.

## Tags

The runners filter asymmetrically, and `specs/README.md` is the source of truth for it. Here:
cucumber-js runs `@ui and not @http-only`. A feature tagged `@ui` has a page to drive; one tagged
`@http-only` — cookie rotation, the OAuth dance, an admin's lever, a policy the compose stack does
not configure — is wire-level and skipped here. A scenario may carry `@http-only` on its own, and
several do.
