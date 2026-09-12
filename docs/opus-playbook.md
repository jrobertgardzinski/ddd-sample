# Playbook dla Opusa — microservice-security

Spisany 2026-07-07 (sesja Fable: „wyciśnij maximum dziś i zaplanuj całość roboty").
Instrukcje wykonawcze: bierz zadania OD GÓRY, jedno zadanie = jedna sesja/commit(y).
Zanim zaczniesz: przeczytaj `todo.md` (stan), `docs/mfa-design.md` (architektura MFA),
`docs/oauth-providers.md` (OAuth). NIE czytaj całych źródeł na zapas — każde zadanie
wskazuje pliki.

## Zasady pracy w tym repo (obowiązują każde zadanie)

- **Heksagon**: domena (`security-domain`) bez frameworka i bez adnotacji; use case'y
  w **`security-system`** (`security-application` NIE MA `src/main` — to warstwa testowa, która
  napędza te use case'y Cucumberem; sprostowane 2026-09-12); stroiki/rekordy konfiguracyjne
  w `security-config`
  (framework-free, defaulty+walidacja w konstruktorze — wzór: `OauthProviderSettings`,
  `ChallengeCodeConfig`); HTTP/JDBC/Kafka/beany tylko w `security-infrastructure`.
  Nowa reguła biznesowa NIGDY nie zaczyna się od kontrolera.
- **Spec-first**: zachowanie opisuje plik w `specs/*.feature` (neutralny katalog — napędza
  wejście HTTP, warstwę application i UI). Nowy scenariusz piszesz PRZED implementacją.
- **Testy trzech wejść**: warstwa application (cucumber JVM), czarna skrzynka po drucie
  (`*HttpTest`), UI (`security-ui/run-e2e.sh`, cucumber-js+Playwright). Zmiana zachowania =
  dotykasz wszystkich wejść, które je widzą.
- **Build**: `./mvnw -q -pl security-infrastructure -am package` (wrapper w TYM repo).
  Testy całości: `./mvnw test`. E2e UI: `cd security-ui && ./run-e2e.sh`.
  Smoke całego stacku: `cd .. && ./infra-smoke.sh` (wymaga `docker compose` z korzenia
  workspace; buduj jary PRZED `docker compose build`).
- **Commit**: angielska, jednolinijkowa, obrazowa wiadomość (wzór: git log), stopka
  `Co-Authored-By: Claude <model> <noreply@anthropic.com>`. Javadoc i komentarze po angielsku.
- **Gotchas**: po przeniesieniu `.feature` → `mvn clean` (stare kopie w target dublują
  scenariusze); POST bez `consumes` po micronaut-data = dwuznaczna trasa; snakeyaml musi
  być na classpath, inaczej yml jest MILCZĄCO ignorowany.

---

## S1. UI jako trzecie wejście — PEŁNE pokrycie specs/ (największe zadanie)

**Cel:** każdy feature ze `specs/`, którego zachowanie jest osiągalne z przeglądarki,
jeździ przez realny UI (cucumber-js + Playwright), tak jak dziś register/authenticate/mfa.
Feature'y czysto drutowe dostają jawny tag i zostają przy wejściach JVM.

**Stan zastany:**
- Runner: `security-ui/e2e/cucumber.mjs` — dziś JAWNA lista 3 plików
  (`register`, `authenticate`, `mfa`), kroki w `security-ui/e2e/steps/*.mjs`,
  świat w `security-ui/e2e/support/world.mjs` (tam mieszkają backdoory testowe,
  m.in. `/test/mailbox/signin-code`).
- Harness: `security-ui/run-e2e.sh` — stawia serwis w env `test` (in-memory, sterowalny
  zegar, przechwycona skrzynka; port 8180) + Vite na 4200.
- Ekrany: `security-ui/src/App.tsx` (jeden plik, tryby przez `useState<Mode>`).
  22/22 e2e zielone na dziś.

**Krok 0 — tagi zamiast listy plików.** Wprowadź tagi `@ui` i `@http-only`:
- Do każdego feature'a w `specs/` dodaj na górze tag `@ui` ALBO `@http-only`
  (decyzje niżej). Tag na poziomie Feature wystarczy; per-scenariusz tylko gdy
  feature jest mieszany.
- `cucumber.mjs`: zamień `paths` na `['../specs/*.feature']` + `tags: '@ui'`.
- Runnery JVM: nie filtruj (JVM napędza wszystko jak dotąd) — tagi są dla UI.
- Dowód kroku 0: `./run-e2e.sh` dalej 22/22 (te same 3 feature'y łapią się przez tag).

**Decyzje tagowania (podjęte; korekta 2026-07-07 po kroku 1):**
- `@http-only`: `authorize.feature` (introspekcja — brak UI), `refresh-session.feature`
  i `reuse-detection.feature` (mechanika cookie/rotacji — przeglądarka robi to sama,
  scenariusze sterują drutem), `federated-sign-in.feature` (taniec z fake providerem —
  UI-owa strona jest już kryta e2e galerii w memes), **`logout.feature`** (KOREKTA:
  unieważnienie sesji jedzie na cookie refresh, którego cross-originowe dev UI nie trzyma —
  fetch bez credentials/SameSite; sign-out w UI mimo to woła POST /logout, co przy
  serwowaniu same-origin unieważnia naprawdę).
- `@ui`: register, authenticate, mfa (są), verify-email, reset-password, change-password,
  change-email, list-sessions, revoke-all-sessions, delete-account.

**Krok 1..N — po JEDNYM feature na commit, w tej kolejności** (od najmniejszego przyrostu
ekranu do największego):

1. **logout.feature** — ekran: przycisk „Sign out" w widoku zalogowanego (jeśli brak).
   Kroki: sign-in helper już jest w `authenticate.steps.mjs` — wydziel do `support/`.
2. **verify-email.feature** — UI ma ekran weryfikacji? Jeśli nie: tryb `verify` czytający
   token z query param (link z maila). Backdoor skrzynki: dopisz w serwisie testowym
   endpoint `/test/mailbox/last-link?type=VERIFY_EMAIL` wzorem `signin-code`
   (szukaj implementacji backdoora po stringu `signin-code` w security-infrastructure;
   backdoor MUSI być ograniczony do env `test`).
3. **reset-password.feature** — tryby `forgot` (podaj email) i `reset` (nowe hasło
   z tokenem z maila). Ten sam backdoor skrzynki, typ RESET.
4. **change-password.feature** — ekran w koncie. UWAGA (aktualizacja 2026-09-12): akcja NIE jest
   pod step-upem — wypadła z katalogu `StepUpAction`; broni jej wpisanie obecnego hasła
   (sprawdzane inline) plus okno na źródło `security.change-password.max-per-window`.
   Flow e2e: sign-in → zmiana.
5. **change-email.feature** — ekran w koncie + potwierdzenie linkiem (backdoor jak
   verify). Pamiętaj o scenariuszu enumeracji (zajęty adres → odpowiedź identyczna).
6. **list-sessions.feature + revoke-all-sessions.feature** — widok „Active sessions"
   z przyciskiem „Revoke all others". Dwa feature'y, jeden ekran — mogą iść razem.
7. **delete-account.feature** — security-ui NIE MA UI delete (todo to odnotowuje).
   Dodaj w koncie sekcję „Danger zone": dialog delete robi step-up FULL_CHAIN
   (hasło → czynnik) wzorem dialogu w galerii memes (`memes-ui/src/DeleteAccountDialog.tsx`
   jako referencja UX, ale pisz od zera w stylu App.tsx). Saga w env `test` działa
   bez Kafki? SPRAWDŹ: jeśli purge-confirm wymaga memes, scenariusz UI kończy się na
   „konto zablokowane, mail pożegnalny po potwierdzeniu" — dopasuj do istniejących
   kroków JVM, nie wymyślaj nowej semantyki.

**Dla każdego kroku:** (a) tag i ewentualny podział scenariuszy; (b) nowe kroki w
`e2e/steps/<feature>.steps.mjs` — te same Gherkiny co JVM, ZERO kopiowania treści
feature'a; (c) brakujący ekran w App.tsx (trzymaj konwencję: fetch, `prettify(code)`
na błędach, stany przez `useState`); (d) `./run-e2e.sh` zielone; (e) commit.

**DoD zadania S1:** wszystkie feature'y otagowane; `cucumber.mjs` na globie+tagu;
każdy `@ui` feature przechodzi przez realny UI; liczba e2e w README security-ui
zaktualizowana; `todo.md` — pozycja „UI jako 3. wejście" oznaczona jako zrobiona.

**Pułapki:** fetch traktuje 4xx jako `r.ok===false`, ale 202 jako ok — bug z fazy G
już naprawiony, nie regresuj; równoległość cucumber-js zostaw na 1 (wspólny serwis);
w env `test` throttling rejestracji wyłączony przez env — nie włączaj.

---

## S2. Odświeżenie linku federacyjnego przy change-email

**Cel:** po zmianie emaila konto z tożsamością federacyjną nie zostaje z martwym linkiem.
Dziś (świadomie odroczone): stały link „bezpiecznie odpada i re-linkuje się przy
następnym logowaniu". Domknij temat jawnie.

**Stan zastany:** `FederatedIdentityRepository` (migracja V10), use case `FederatedSignIn`,
use case zmiany adresu w `security-system/.../account` (`RequestEmailChange`, `ConfirmEmailChange`).

**Kroki:**
1. Przeczytaj scenariusze `change-email.feature` i `federated-sign-in.feature`.
2. Dopisz scenariusz (application layer, `@http-only` nie dotyczy — to nie UI):
   „konto z tożsamością Google zmienia email → stara tożsamość federacyjna zostaje
   ODPIĘTA w momencie POTWIERDZENIA nowego adresu; logowanie Google z NOWYM emailem
   linkuje się na powrót przy pierwszym federacyjnym logowaniu" — czyli formalizujesz
   dzisiejsze zachowanie + jawne odpięcie zamiast osieroconego wiersza.
3. Implementacja: w potwierdzeniu change-email wywołaj
   `FederatedIdentityRepository.removeAllFor(userId)` (dodaj metodę, jeśli brak;
   JDBC + in-memory). Decyzja projektowa: NIE przepinamy linku automatycznie na nowy
   email — provider nie poręczył nowego adresu; re-link zrobi się sam przy następnym
   OAuth (istniejąca ścieżka auto-link dla zweryfikowanego konta).
4. Testy: scenariusz z p.2 + przypadek w `OauthFlowHttpTest` (stary link po zmianie
   emaila nie loguje na stare konto w trybie „squatter takeover" — musi przejść ścieżką
   świeżego/auto-link zgodnie ze stanem weryfikacji).
5. `todo.md`: skreśl „odświeżanie linku federacyjnego przy change-email".

**DoD:** testy zielone; zachowanie opisane w docs/oauth-providers.md (sekcja „email
change & federated identities", 5–10 zdań).

---

## S3. WebAuthn/passkeys jako trzeci czynnik plug-and-play (flagowe, duże)

**USTALENIA Z ANALIZY 2026-07-07 (Fable) — reguła stopu zadziałała zgodnie z planem.**
Port PRZEŻYWA, ale wymaga dwóch JAWNYCH, addytywnych korekt (nie hacków). Wykonuj wg tego,
sekcja poniżej („zakres minimalny") pozostaje ważna tam, gdzie nie koliduje:

1. **ZERO CBOR i zero zależności**: NIE parsuj attestationObject. Przeglądarka wystawia
   klucz wprost: `AuthenticatorAttestationResponse.getPublicKey()` → **SPKI DER** i
   `getPublicKeyAlgorithm()` (−7=ES256). Enrolment-proof = JSON-string
   `{credentialId, publicKey(b64url SPKI), algorithm, clientDataJSON(b64url)}` — kontrakt
   endpointów bez zmian (proof zawsze był stringiem). Assertion przy logowaniu = JSON-string
   `{credentialId, clientDataJSON, authenticatorData, signature}` (wszystko b64url);
   weryfikacja czystym JDK: parse authenticatorData ręcznie (rpIdHash 32B + flags 1B +
   signCount 4B), podpis `SHA256withECDSA` nad `authenticatorData || SHA256(clientDataJSON)`
   kluczem z SPKI (`KeyFactory EC`). **Żadnej migracji V14**: credential JSON mieszka w
   `EnrolledFactor.secretMaterial` — repozytorium już to persystuje.
2. **Korekta portu #1 (enrolment)**: `AuthenticationFactor` dostaje
   `default String enrolledMaterial(String pendingMaterial, String proof) { return pendingMaterial; }`
   — a `EnrolFactor.confirm` zapisuje `factor.enrolledMaterial(pending, proof)` zamiast
   surowego pending. Default zachowuje wszystkie istniejące czynniki; WebAuthn nadpisuje
   (wyciąga credential z proofa PO pozytywnym verify; verify przy confirm sprawdza podpis
   challenge'u z clientDataJSON przeciw `Challenge.codeHash`).
3. **Korekta portu #2 (sign-in, ŚWIADOMA zmiana drutu)**: klient musi dostać nonce.
   `issueChallenge` WebAuthn mintuje losowy nonce → `Challenge(sha256(nonce), expiry)`
   (schemat Challenge bez zmian), ale SUROWY nonce musi wyjechać w 202. Dodaj pole
   `String challengeData` (nullable) do TRZECH rekordów wyników:
   `AuthenticationResult.MfaRequired`, `FederatedSignInResult.MfaRequired`,
   `StepUp.Result.FactorRequired` — oraz przewlecz w `MfaChain` (skąd pochodzi challenge),
   kontrolerach (`/authenticate`, `/authenticate/factor`, `/oauth/callback` fragment,
   `/account/step-up[.../factor]`) jako pole `challengeData` w body 202, i w
   `EnrolFactor.Result.Started.display` (creation options JSON dla enrolmentu już ma
   swój kanał — `display`). Aktualizuj bots/... nie — aktualizuj `MfaHttpTest`,
   `StepUpHttpTest` i UI obu aplikacji (pole ignorowane przez stare czynniki = null).
   W clientDataJSON challenge NIE jest hashem — porównuj `sha256(base64urlDecode(
   clientData.challenge))` z `codeHash`; verify sprawdza też `type`
   (`webauthn.get`/`webauthn.create`), `origin` (config: `security.webauthn.origins`,
   default localhost:4200/8080) i `rpIdHash`.
4. **E2e**: Playwright CDP `WebAuthn.enable` + `addVirtualAuthenticator` (ctap2/internal,
   automaticPresenceSimulation) — scenariusz w mfa.feature taguj `@ui`; JVM-owy odpowiednik
   w MfaHttpTest z nagranym fixture z wirtualnego authenticatora (zapisz payloady z sesji
   e2e do zasobów testowych) LUB zbuduj assertion w teście własnym kluczem EC (prościej:
   wygeneruj keypair w teście, złóż clientDataJSON+authenticatorData ręcznie, podpisz).
5. Kolejność: (a) port+EnrolFactor+rekordy+kontrolery z challengeData (testy JVM zielone,
   stare czynniki nietknięte — challengeData=null); (b) `WebauthnFactor` + unit na własnym
   kluczu EC; (c) UI enrolment/sign-in (`navigator.credentials.create/get`, mapowanie
   b64url); (d) e2e z wirtualnym authenticatorem; (e) mfa-design.md sekcja „Phase H".

**Cel:** dowód architektury z `docs/mfa-design.md` — nowa metoda = nowy adapter,
zero zmian w rdzeniu. Po TOTP naturalny następny czynnik: WebAuthn (passkeys).

**PRZECZYTAJ NAJPIERW:** docs/mfa-design.md (port `AuthenticationFactor`,
`EnrolmentSetup`/`beginEnrolment` — dodane w fazie B; egzekutor `MfaChain`).

**Zakres minimalny (MVP, bez biblioteki zewnętrznej — decyzja: możesz użyć
`com.webauthn4j:webauthn4j-core` JEŚLI czyste-JDK parsowanie CBOR/COSE okaże się
za drogie; wybór odnotuj w commit message):**
1. `WebauthnFactor implements AuthenticationFactor` w security-infrastructure
   (adapter, nie domena): `beginEnrolment` → wygeneruj challenge + PublicKeyCredentialCreationOptions
   (JSON dla UI), `confirmEnrolment` → zweryfikuj attestation „none", wyciągnij
   klucz publiczny (COSE) i credentialId, zapisz; `challenge`/`verify` przy logowaniu →
   assertion: podpis nad authenticatorData+clientDataHash, sprawdź rpIdHash/origin/
   counter. Storage: nowa migracja `V14 webauthn_credentials`
   (user_id, credential_id, public_key_cose, sign_count, created_at).
2. Rejestr: nowy bean wpięty w `FactorRegistry` — NIC więcej w rdzeniu (to jest teza
   do udowodnienia; jeśli musisz dotknąć MfaChain — zatrzymaj się i opisz w todo
   dlaczego, to sygnał że port wymaga korekty, nie hackuj).
3. Endpointy: istniejące `/account/factors` (enroll/confirm) i `/authenticate/factor`
   niosą JSON-owe payloady czynnika — sprawdź, czy kontrakt przepuszcza obiekt
   (TOTP przepuszcza string); w razie potrzeby payload czynnika = string z JSON-em,
   parsowany w adapterze (kontrakt bez zmian).
4. UI: App.tsx — `navigator.credentials.create/get` w managerze enrollmentu i kroku
   czynnika. E2e: Playwright ma **virtual authenticator** (CDP `WebAuthn.enable` +
   `WebAuthn.addVirtualAuthenticator`) — dopisz scenariusz do mfa.feature z tagiem
   `@ui` i krokami używającymi wirtualnego klucza.
5. Testy: unit adaptera na wektorach (zbuduj fixture przez webauthn4j test utils albo
   nagraj payload z virtual authenticatora); `MfaHttpTest` — enrollment+logowanie po
   drucie z podrobionym assertion (odmowa) i prawdziwym (fixture); smoke NIE (brak
   przeglądarki w stacku) — odnotuj w skrypcie smoke komentarzem.

**DoD:** ADMIN może mieć łańcuch hasło+TOTP+passkey (floor 3 bez SMS-a); mfa-design.md
dostaje sekcję „Phase H: WebAuthn — what the port survived"; todo.md zaktualizowane.

---

## S4. Realny Google jako provider (ZABLOKOWANE na usera)

Czeka na client-id/secret od usera (konsola Google). Gdy je dostaniesz:
przepis JEST w `docs/oauth-providers.md` — dodaj wpis `security.oauth.providers.google-real.*`
w compose/prod env, przetestuj ręcznie start→callback na deployu, nic w kodzie.
NIE zaczynaj bez credentiali. Przypomnij userowi przy okazji sesji.

## ~~S5. Porządki gałęzi remote-only~~ — ZAMKNIĘTE

Gałęzie, o które chodziło, już nie istnieją (sprawdzone 2026-09-09 i ponownie 2026-09-12).
Zasada zostaje: cudzych gałęzi nie kasujesz sam — pytasz.
