# TODO

Tylko otwarte rzeczy. Historia zrobionego = git log.
(Stara wersja z pełnym logiem faz: git log tego pliku.)

**Plan pracy z instrukcjami wykonawczymi: [docs/opus-playbook.md](docs/opus-playbook.md)**
(2026-07-07; S1, S2, S3 ZROBIONE. S3 WebAuthn WDROŻONY W CAŁOŚCI (kroki a–e):
wire (`Challenge.publicData`→`challengeData` w 202, port `enrolledMaterial`),
`WebauthnFactor` (czysty JDK, SPKI, zero CBOR/migracji), UI (create/get + auto-krok),
e2e na wirtualnym authenticatorze; Faza H w docs/mfa-design.md. 178 testów JVM +
36 e2e zielone. S5 zamknięte (gałęzie już nie istniały; runda 2 czeka). S4 na userze.)

## Stan (2026-07-02) — kontekst, nie backlog

**13 feature'ów w `specs/`**, każdy napędzany czarną skrzynką przez HTTP (+ warstwa application
dla części): Register, Authenticate (+brute-force; od 2026-07-02 wymaga zweryfikowanego
emaila — 403 `EMAIL_NOT_VERIFIED`, rejestracja auto-wysyła link), RefreshSession
(+reuse-detection), Authorize, Logout, Verify email (request+confirm), Reset hasła
(request+complete), Change password, Change email (z re-weryfikacją nowego adresu; potwierdzenie
oznacza nowy adres jako zweryfikowany), Delete account (RODO), List active sessions,
Revoke all sessions. Persystencja: Micronaut Data JDBC + Flyway + Testcontainers (in-memory,
gdy brak datasource). Deployment: docker-compose (Postgres + serwis). Maile: od 2026-07-02 **zdarzenia przez Kafkę**
— transactional outbox w Postgresie (`outbox_events`, V5; ta sama transakcja co zmiana stanu),
poller publikuje na topik `mail-requests`, konsumuje `microservice-email` (at-least-once,
dedup po id zdarzenia). Awaria mail-serwisu nie psuje rejestracji — zdarzenie czeka.
**Delete account jest sagą** (orkiestracja, stan w `account_deletion_sagas`, V6): konto blokuje się
od razu (`users.pending_deletion`), memes czyści treści (komenda `memes-commands` przez outbox,
potwierdzenie `memes-events`), dopiero potwierdzenie kasuje usera i wysyła mail pożegnalny;
brak potwierdzenia w limicie (`account-deletion.purge-timeout`, domyślnie 2 min) = kompensacja
(odblokowanie + mail z przeprosinami).

## Przegląd 2026-09-08 — naprawy (raport: `docs/review-2026-09-08.md`)

Kolejność pracy = sekcja „Suggested order of work" w raporcie. Jedna paczka = jeden commit
+ reguła w `specs/`. Pozycje zmieniające kształt domeny/use-case'ów (DOM-2, DOM-9, DOM-12,
DB-8, `Source` w `PendingAuthentication`) są decyzją właściciela — tylko wypisane, nie robione.

- **MFA-1 (CRITICAL) — ZROBIONE 2026-09-12.** Koperta `webauthn.create` przyjmowana przy
  logowaniu i step-upie (obejście passkeya samym hasłem). `WebauthnFactor.verify` akceptuje
  gałąź `create` wyłącznie dla zapisu PENDING (puste `secretMaterial`); zapisany czynnik
  zawsze niesie `{credentialId,publicKey}`, więc przy logowaniu i step-upie zostaje tylko
  podpisana asercja `webauthn.get`. Dowód: `WebauthnFactorTest` (jednostkowo) +
  `MfaHttpTest.webauthn_enrolment_envelope_does_not_sign_in` (po HTTP, logowanie i step-up),
  oba sprawdzone na czerwono przed poprawką. Reguła: `specs/mfa-passkey.feature`
  (warstwa przeglądarkowa — NIE chodzi w CI, tylko `run-e2e.sh`).
- Następne wg raportu: ACC-1 → AUTH-3 (+ACC-4, DOM-2) → HTTP-1/HTTP-2 (przed PLAN-P12 K1) →
  throttle'y (AUTH-2, ATK-4) → DOM-1 → OPS-1 → UI-1/UI-2 → ACC-2 → obsługa błędów brzegowych →
  wyścigi → config na starcie → przegląd dokumentacji.

## Otwarte — pilne (2026-08-08)

- **~~Cztery scenariusze przeglądarkowe MFA są czerwone~~ — COFNIĘTE 2026-08-08.** Sprostowanie:
  to NIE był dług sprzed sierpnia. Browser e2e było 36/36 zielone jeszcze o 10:09 tego dnia;
  cztery scenariusze położyła paczka `a2bf62c` (wygaszanie linków zmiany adresu + step-up na
  kodach odzyskiwania), zacommitowana z drzewa roboczego bez sprawdzenia suity przeglądarkowej.
  Revert przywrócił 36/36; praca czeka na gałęzi **`wip-email-change-expiry`**.
  **Do dokończenia przed powrotem na main:** (1) UI musi dokończyć czynnikową połowę step-upu —
  bilet `FACTOR_REQUIRED` przychodzi, a `/account/step-up/factor` nie jest wołane ani razu w całej
  suicie (także przez scenariusze, które przechodzą, bo ich konta elewują się na samym haśle;
  `StepUp` linia 73); (2) scenariusz zmiany adresu przestaje dostawać maila po dołożeniu okna
  ważności. Ślad sieciowy niżej zostaje aktualny — dotyczy tamtej gałęzi.
  Objaw był taki: `getByTestId('recovery-codes')`
  nigdy się nie pojawia. Połowa przyczyny naprawiona (UI nie pytał o step-up przy generowaniu
  kodów — przycisk był martwy także dla użytkownika, nie tylko w teście). Zostaje: dla konta
  Z zapisanym czynnikiem serwer zwraca 202 FACTOR_REQUIRED, a pole na kod się nie renderuje.
  **Ślad sieciowy z podsłuchu w przeglądarce (2026-08-08), od tego zacząć:**
  ```
  POST /account/recovery-codes -> 403 {"status":"STEP_UP_REQUIRED","action":"generate-recovery-codes"}
  POST /account/step-up        -> 202 {"stepUpTicket":"...","nextFactor":"EMAIL_CODE","status":"FACTOR_REQUIRED"}
  POST /account/step-up        -> 200 {"status":"ELEVATED"}      <-- DRUGI start, zamiast /step-up/factor
  POST /account/recovery-codes -> 403 {"status":"STEP_UP_REQUIRED"}
  ```
  Czyli: bilet przychodzi, ale UI zamiast dokończyć łańcuch (`/account/step-up/factor`) startuje
  step-up od nowa — i elewacja, którą wtedy dostaje, nie otwiera tego endpointu. `/step-up/factor`
  nie jest wołane ANI RAZU w całym przebiegu suity, także przez scenariusze, które PRZECHODZĄ:
  ich konta elewują się na samym haśle (`StepUp` linia 73 — hasło jest wymagane tylko dla
  FULL_CHAIN albo gdy lista czynników jest pusta). Czynnikowa połowa step-upu w UI nie ma więc
  żadnego pokrycia i to jest prawdziwa dziura, nie sam czerwony scenariusz.

  Sprawdzone i WYKLUCZONE: limit step-upu (429 — podniesiony w compose, nie zmienia wyniku),
  wersja Node (suita wymaga 22+, lokalnie zainstalowany przez nvm), strona serwera (ręcznie
  curl-em: step-up z akcją `generate-recovery-codes` → ELEVATED → POST zwraca dziesięć kodów).

## Otwarte — use case'y / security

- ~~OAuth/social login~~ — ZROBIONE (2026-07-05): taniec Authorization Code + PKCE (S256) na
  brzegu — `/oauth/{provider}/start` + `/oauth/callback` (state jednorazowy, TTL 10 min, nonce,
  return-URL tylko z allowlisty, access token wraca FRAGMENTEM, refresh jak zwykle w HttpOnly
  cookie); `OidcClient` (czysty JDK HttpClient) wymienia kod i waliduje id_token: HS256
  weryfikowany client-secretem (stub), algorytmy asymetryczne (Google RS256) na mocy
  bezpośredniego kanału TLS wg OIDC Core 3.1.3.7 — iss/aud/exp/nonce twardo zawsze. Provider =
  czysty config (@EachProperty `security.oauth.providers.*`): w compose „google" wskazuje STUB
  IdP (`microservice-idp`, Python stdlib, :8091 — 8090 zajęte przez race-sim), prod podmienia
  URL-e i client-id/secret. Use case `FederatedSignIn` + VO `ProviderIdentity` +
  `FederatedIdentityRepository` (migracja V10; jedno konto — wiele tożsamości): świeży email →
  konto od urodzenia zweryfikowane i BEZHASŁOWE (hash odrzuconego losowego sekretu; hasło można
  nadać resetem); konto ZWERYFIKOWANE → auto-link, hasło nietknięte; NIEZWERYFIKOWANE (squatter)
  → przejęcie: link + verified + hasło skasowane + revoke wszystkich sesji; email bez poręczenia
  providera nie tyka niczego; pending-deletion odmawia jak przy haśle.
  `federated-sign-in.feature` (5 scenariuszy, warstwa application) + `OauthFlowHttpTest` (pełny
  taniec po drucie z fake'owym providerem: replay state'a, zły nonce, cudzy return-URL) + krok
  w infra-smoke (PASS live). Mail „already registered" podpowiada logowanie społecznościowe /
  ustawienie hasła resetem; UI galerii ma przycisk „Sign in with Google". ZOSTAJE na później:
  realny Google (client-id/secret od usera — ZABLOKOWANE na usera, przepis w docs/oauth-providers.md).
  ~~Odświeżanie linku federacyjnego przy change-email~~ — ZROBIONE (2026-07-07, playbook S2):
  potwierdzenie zmiany emaila JAWNIE odpina wszystkie tożsamości federacyjne
  (`FederatedIdentityRepository.unlinkAll`, in-memory + JDBC `deleteByUserEmail`);
  bez auto-przepięcia — provider poręczył stary adres, re-link przy następnym federacyjnym
  logowaniu ścieżką auto-link. Reguła w change-email.feature (HTTP glue), unit w
  ConfirmEmailChangeTest, sekcja w docs/oauth-providers.md.
  - ~~Uogólnienie na Facebook/GitHub/GitLab~~ — ZROBIONE (2026-07-06): `identity-source`
    per provider — `ID_TOKEN` (Google/GitLab, jak dotąd) albo `USERINFO` (Facebook/GitHub:
    exchange kodu → access_token → GET userinfo; mapowanie pól `subject-field`/`email-field`/
    `email-verified-field`, opcjonalny `emails-url` GitHub-shaped — primary verified wygrywa,
    `assume-email-verified` jako świadoma decyzja deploymentu — bez niej brak flagi =
    `EMAIL_NOT_VOUCHED`); `scope` i `label` per provider; `GET /oauth/providers` → UI galerii
    rysuje przyciski dynamicznie (dodanie providera = tylko config). W compose drugi provider
    „github" na TYM SAMYM stubie ćwiczy USERINFO; smoke kryje obie ścieżki (PASS live).
    Przepisy configu realnych providerów: [docs/oauth-providers.md](docs/oauth-providers.md).
    `OauthFlowHttpTest`: 6 testów (dotychczasowe + hub/emails-url + faces/assume + strict/refused
    + listing providerów). Ustawienia providera = `OauthProviderSettings` w WARSTWIE CONFIG
    (framework-free rekord, defaulty+walidacja w konstruktorze; widoczny w glosariuszu UL);
    infra tylko binduje propertisy (@EachProperty shim → @EachBean w BeanFactory).
- **MFA: łańcuch czynników, metody PLUG-AND-PLAY, minimum per rola** — flagowy „wow"; największy
  otwarty temat. PEŁNY PROJEKT: [docs/mfa-design.md](docs/mfa-design.md) (2026-07-05). Skrót:
  port `AuthenticationFactor` + `FactorRegistry` = dodanie metody (TOTP/Google Authenticator,
  WebAuthn…) to nowy adapter-bean, zero zmian w rdzeniu (email/SMS to tylko dwa adaptery); egzekutor
  łańcucha (`PendingAuthentication` + ticket, jak OauthFlowStore) mintuje sesję dopiero po ostatnim
  ogniwie; `MfaPolicy` wymusza minimum per rola (USER 1 / MODERATOR 2 / ADMIN 3, konfig) w TRZECH
  miejscach — brama logowania (sesja `enrolment_only` dla niedopełnionych), grant roli (`/me`
  `mfaCompliant`), usuwanie czynnika (podłoga); bootstrap-admin grace do pierwszego enrollmentu.
  Fazy A–G w dokumencie. 4 decyzje usera ROZSTRZYGNIĘTE (2026-07-05): floor liczy cały łańcuch
  z pierwszym; niedopełniony → sesja enrolment-only; federacyjni do PEŁNEGO floora (OAuth się nie
  liczy); pierwszy factor = e-mail (TOTP w fazie B).
  - ~~FAZA A~~ — ZROBIONE (2026-07-05): port `AuthenticationFactor` + `FactorRegistry` +
    egzekutor łańcucha (`PendingAuthentication` + jednorazowy ticket w `PendingAuthenticationStore`)
    + `EmailCodeFactor` nad portem `CodeChannel` (outbox `AUTH_CODE` prod / capturing test);
    `Authentication` rozgałęzia po bramie zweryfikowanego maila (brak czynników = sesja jak dawniej;
    są = 202 `MFA_REQUIRED` + ticket), `ContinueAuthentication` domyka; enrollment `EnrolFactor`
    (start wysyła kod, confirm pieczętuje). `ChallengeCodeConfig` (TTL/próby/długość, default 5/5/6)
    w warstwie config; kody SHA-256 hash. Migracja V11 `enrolled_factors`. Endpointy: `/authenticate`
    (202), `/authenticate/factor`, `/account/factors` (list/enroll/confirm/remove). Mail `AUTH_CODE`
    w microservice-email. UI: security-ui (dwustopniowe + enrollment) i galeria memów (krok kodu).
    Testy: `mfa.feature` (application) + `MfaHttpTest` (po drucie) + krok w infra-smoke (live).
  - ~~FAZA B~~ — ZROBIONE (2026-07-05): `EmailCodeFactor` → generyczny `CodeFactor(kanał)` — email i
    SMS to dwie instancje jednej klasy (nowy kanał = nowy bean, nie nowy factor); `HttpSmsCodeChannel`
    → microservice-sms; `TotpFactor` (RFC 6238/HMAC-SHA1, Google Authenticator) — factor posiadania,
    enrollment mintuje sekret + otpauth URI, nic nie wysyła. Port zyskał `beginEnrolment`
    (`EnrolmentSetup`: secret, co pokazać, opcjonalny challenge). Testy: `TotpFactorTest` (wektor RFC),
    `MfaHttpTest` (TOTP po drucie), smoke (TOTP live). UI: manager enrollmentu (wszystkie oferowane
    metody). SMS: unit+HTTP (stub nie ma czytelnej skrzynki na live).
  - ~~FAZA C~~ — ZROBIONE (2026-07-05, drugi twardy wymóg usera): `MfaPolicy` (min per rola USER 1/
    MOD 2/ADMIN 3, konfig); `MfaCompliance` liczy cały łańcuch (hasło jako #1 + czynniki; konta
    federacyjne PASSWORDLESS — nowa tabela V12, ustawiana przy federated create/takeover, czyszczona
    przy resecie hasła → OAuth NIE liczy się do floora). Egzekwowanie w 3 miejscach: brama
    (`AuthorizationFilter` wpuszcza niedopełnionego tylko do /me i /account/factors, reszta 403
    `MFA_ENROLMENT_REQUIRED` — sesja realna, „zabudowana"), grant (`/me` niesie
    mfaCompliant/requiredFactors/haveFactors), usuwanie (409 `WOULD_BREAK_MFA_FLOOR`). Bootstrap-admin
    grace do pierwszego enrollmentu. UI nudge. `MfaRoleFloorHttpTest` (pełny łuk) + `MfaPolicyRulesTest`.
    ODSTĘPSTWO od doc: żywe sprawdzanie compliance w filtrze zamiast trwałej flagi `enrolment_only`
    na wierszu sesji — prościej (bez zmian schematu sesji) i poprawniej (aktualizuje się natychmiast
    po enrollmencie, bez re-logowania).
  - ~~FAZA F~~ — ZROBIONE (2026-07-05): OAuth to tylko ogniwo #1. `_MfaChain` → publiczny `MfaChain`
    (jeden bean: logowanie hasłem, federacyjne, kontynuacja). `FederatedSignIn` po rozwiązaniu konta
    sprawdza czynniki: brak → sesja, są → `MfaRequired` + ticket w tym samym store; callback OAuth
    zwraca `#mfaTicket`, galeria dokańcza przez `/authenticate/factor`. Zamyka dziurę z fazy C
    (federacyjny admin z czynnikami był wpuszczany bez nich). Scenariusz w federated-sign-in.feature.
  - ~~FAZA E~~ — ZROBIONE (2026-07-05): step-up. `StepUpPolicy` (per akcja NONE/SECOND_FACTORS/
    FULL_CHAIN; delete=FULL_CHAIN, change-password=SECOND_FACTORS, config). `StepUp` odpala łańcuch na
    żywej sesji (FULL_CHAIN = najpierw hasło, potem czynniki przez wspólny `MfaChain`), po ostatnim
    czynniku mintuje jednorazowy `SessionElevation` na access-tokenie. `DeleteAccountController` konsumuje
    elewację przez `StepUpGuard` (403 `STEP_UP_REQUIRED` bez niej — skradziona sesja nie usunie konta).
    Endpointy `/account/step-up` (+`/factor`). `StepUpHttpTest` (ścieżka hasłowa i czynnikowa), dialog
    delete w galerii robi step-up, saga w smoke poprzedzona step-upem. Live PASS.
  - ~~FAZA D — admin reset~~ — ZROBIONE (2026-07-05): `PUT /admin/users/{email}/factors/reset`
    (ADMIN + step-up), `EnrolledFactorRepository.removeAll`; użytkownik po resecie spada pod podłogę.
    `AdminFactorResetHttpTest`.
  - ~~recovery codes~~ — ZROBIONE (2026-07-06), dokładnie jako czynnik ALTERNATYWNY (nie ogniwo):
    `MfaChain.verify` po odmowie czynnika próbuje skonsumować nieużyty recovery code (normalizacja
    case/myślników → SHA-256 → warunkowy UPDATE, więc jednorazowość jest atomowa) — sign-in
    continuation i step-up łapią to bez własnych zmian. `RecoveryCodeRepository` (V13, spent
    zostaje wierszem — UI mówi „N z 10"), `GenerateRecoveryCodes` (alfabet bez homoglifów, grupy
    po 5) + `RecoveryCodeConfig` (warstwa config). `POST /account/recovery-codes` pokazuje batch
    RAZ i unieważnia stary; `GET` = licznik. UI: security-ui generuje/liczy + hint na ekranie
    kodu; galeria hint. Testy: mfa.feature (2 scenariusze), MfaHttpTest (spend/replay/regeneracja),
    infra-smoke krok. Szczegóły w docs/mfa-design.md.
  - ~~FAZA G — MFA w e2e security-ui~~ — ZROBIONE (2026-07-06): mfa.feature (5 scenariuszy, w tym
    oba recovery) przez realny UI (cucumber-js/Playwright, wspólne Gherkiny); backdoor
    `/test/mailbox/signin-code` (AUTH_CODE); recovery codes zbierane ze strony po generacji —
    jedyne miejsce, gdzie plaintext istnieje. 22/22 e2e. Znalazło i naprawiło realny bug UI:
    fetch `r.ok` true dla 202 → gałąź MFA martwa po rebuildzie na Reacta (signIn + submitFactor).
    Poza zakresem e2e security-ui: TOTP (MfaHttpTest+smoke), step-up przy delete (galeria+smoke;
    security-ui nie ma UI delete).
  - ~~FAZA H — WebAuthn / passkeys~~ — ZROBIONE (2026-07-07, S3 playbooka): flagowy dowód
    plug-and-play — czynnik INNEGO KSZTAŁTU (podpis, nie kod) dodany BEZ biblioteki i BEZ
    migracji, egzekutor łańcucha nietknięty. Dwie addytywne korekty portu: `enrolledMaterial`
    default (sekret przychodzi z proofem — klucz publiczny generuje przeglądarka) i
    `Challenge.publicData`→`challengeData` w czterech 202 (klient dostaje nonce do podpisu).
    `WebauthnFactor` czysto JDK: SPKI z `getPublicKey()` (zero CBOR/COSE), assertion =
    `SHA256withECDSA` nad `authenticatorData‖SHA256(clientDataJSON)`; credential w
    `EnrolledFactor.secretMaterial`. UI: `navigator.credentials.create/get` (enroll w jednym
    geście, sign-in automatyczny). Testy: WebauthnFactorTest (klucz P-256 gra przeglądarkę),
    MfaHttpTest (enroll→sign-in po drucie + podrobiony assertion), mfa-passkey.feature e2e na
    wirtualnym authenticatorze Chromium. Gotcha: dwukropki URL w defaulcie `@Value` → backticki.
    Faza H w [docs/mfa-design.md](docs/mfa-design.md). 178 JVM + 36 e2e zielone.
- **Step-up auth** — WPISANE W PROJEKT MFA (faza E, [docs/mfa-design.md](docs/mfa-design.md)):
  ten sam egzekutor łańcucha odpalony na żywej sesji → jednorazowy znacznik `elevated`; polityka
  per akcja w configu NONE/SECOND_FACTORS/FULL_CHAIN (delete-account=FULL_CHAIN,
  change-password=SECOND_FACTORS, enrol/remove i admin-reset=SECOND_FACTORS). Odpowiedź na dawne
  pytanie usera (credentials vs credentials+kod): to WARTOŚĆ W CONFIGU per akcja, nie jedno-lub-drugie.
- ~~Role/permissions (RBAC)~~ — ZROBIONE W CAŁOŚCI. Serwerowo (2026-07-04, model 1 płaski):
  enum `Role` (USER/MODERATOR/ADMIN) w domenie; `User` niesie zbiór ról (USER zawsze), port
  `setRoles`, kolumna `roles` (migracja V8, comma-set, in-memory i JDBC), `/me` zwraca role —
  źródło prawdy dla innych serwisów. Endpoint admina `PUT /admin/users/{email}/roles` (use case
  `SetUserRoles`) za drugą bramą: wołający musi być ADMIN — z DB albo z bootstrapu
  `security.bootstrap-admins`. Strona konsumencka TEŻ ZROBIONA (2026-07-04, w sub-repo):
  memes (`50557b7`…`5dcdf70`) i comments (`3dcfc2a`) mają `Caller{email,roles}` z `/me`,
  DELETE mema/komentarza — autor swój, MODERATOR/ADMIN cudzy; testy + Gherkin w obu.
  Powiązany otwarty temat w memes/todo.md: flaga NSFW (moderator ukrywa/odkrywa treść).
- ~~Enumeracja na `/register`~~ — ZROBIONE (2026-07-05, decyzja usera): zajęty adres odpowiada
  IDENTYCZNIE jak świeża rejestracja (201, `{"status":"CHECK_YOUR_MAILBOX"}`, bez `id`); prawda
  idzie mailem do właściciela adresu — niezweryfikowany dostaje świeży link (pewnie zgubił
  pierwszy), zweryfikowany notkę „masz już konto" (nowy port `RegistrationNoticeNotifier`,
  outbox typ `ALREADY_REGISTERED`, szablon w microservice-email). Hash liczony zawsze przed
  sprawdzeniem zajętości (bez kanału czasowego). Rule 3 register.feature przepisana na „quiet
  refusal"; kroki delete-account („email nie jest wolny"/„można znów") dowodzą przez kanał
  mailowy, nie status. `RegisterEnumerationHttpTest` przybija nierozróżnialność.
  Analogiczna enumeracja na `/account/email` — TEŻ ZAMKNIĘTA (2026-07-05): zajęty adres
  odpowiada jak świeży request (202 EMAIL_CHANGE_LINK_SENT), właściciel dostaje notkę mailem
  (ten sam port `RegistrationNoticeNotifier`); reguła + scenariusz w change-email.feature.
- ~~Hardening rejestracji (throttling)~~ — ZROBIONE (2026-07-04): throttle okna stałego per-IP
  (`security.registration.max-per-window` default 5 / `window-minutes` 15, 0 wyłącza),
  sprawdzany PRZED kosztowną pracą (Argon2 + insert), 429 + Retry-After; źródło = spoof-odporny IP
  z `ClientIpResolver`. Unit (3) + HTTP test (429) + live na PG.
- ~~Throttling na pozostałe kosztowne wejścia~~ — ZROBIONE (2026-07-05): `RegistrationThrottle`
  uogólniony do `SourceThrottle` (pakiet `system/throttle`); osobne instancje (@Named, osobne
  okna — burst na jeden endpoint nie zjada drugiego) dla `/register`,
  `/reset-password/request` (`security.password-reset.*`) i `/verify-email/request`
  (`security.verification.*`), oba defaulty 5/15 min, 0 wyłącza; 429 + Retry-After
  (TOO_MANY_RESET_REQUESTS / TOO_MANY_VERIFICATION_REQUESTS). Celowo OSOBNO od guarda
  uwierzytelniania (tamten broni kont przed zgadywaniem haseł, ten serwisu przed wolumenem).
  `RequestThrottleHttpTest` (3), unit throttle bez zmian. Compose podnosi limit rejestracji
  do 100 (smoke rejestruje kilka kont z jednego IP).
- ~~JWT self-contained~~ — ZROBIONE (2026-07-05) jako UZUPEŁNIENIE, nie zamiana: wartość access
  tokena to podpisany JWS (EdDSA/Ed25519, czyste JDK — zero nowych zależności) z iss/sub/roles/
  iat/exp/jti; port domenowy `AccessTokenMint` (RANDOM w unit testach, `JwtAccessTokenMint` w
  infra), mintowany przy authenticate I refresh. Security dalej traktuje wartość jako opaque
  (hash w bazie, introspekcja) ⇒ logout/revoke-all natychmiastowe. Inne serwisy MOGĄ weryfikować
  offline: `GET /.well-known/jwks.json` (OKP/Ed25519, kid) — kompromis świadomy: offline nie
  widzi logoutu/zmiany ról do wygaśnięcia; kto chce natychmiastowości, woła `/me` jak dotąd.
  Klucze: `security.jwt.private-key`/`public-key` (base64 PKCS#8/X.509), brak = efemeryczne
  (restart psuje TYLKO weryfikację offline — w stronę bezpieczną). `JwtAccessTokenHttpTest`:
  weryfikacja podpisu przez JWKS + logout zabija ważny podpisowo token. Zweryfikowane live.
  EWENTUALNY NASTĘPNY KROK: konsument (memes/comments) weryfikujący offline zamiast /me.
- ~~`Source` jako podmiot domeny~~ — ZROBIONE (2026-07-05): VO `Source(ipAddress, userAgent)`;
  TOŻSAMOŚĆ = samo IP (jedyne pole w equals/hashCode — klucz bloków i liczników; podsieć/ASN
  mogą kiedyś doostrzyć tę oś), OBSERWOWANE = userAgent (forensyka, celowo POZA equals — pin
  w `_BruteForceGuardTest`: rotacja user-agenta trafia w TEN SAM blok). `AuthenticationRequest`/
  `AuthenticationBlock`/guard/repozytoria biorą `Source`; kontroler dokłada nagłówek User-Agent
  z brzegu. Persystencja: `rejected_authentications.user_agent` (V9) — RODO: żyje dokładnie tak
  długo jak rekordy porażek (czyszczone razem); bloki trzymają samo IP (odtworzony `Source` bez
  kontekstu obserwowanego). Zweryfikowane live (V9 + kolumna wypełniana). Rozważane kiedyś:
  `DeviceFingerprint`/`RequestContext`, gdy obserwowanych atrybutów przybędzie.

## Otwarte — specs: rejestracja → aktywacja jako PROCES (2026-09-02, do przemyślenia)

Ustalenia z rozmowy 2026-09-02 (Robert: „nie mam teraz do tego głowy" — nic nie wdrożone).
Kontekst i reguła katalogu: `specs/README.md` (literały = próbki stopnia Rebuild, tagi asymetryczne).

**Problem.** `register.feature` Rule 1 („the USER is REGISTERED") jest zielony, ale dowodzi tylko
odpowiedzi systemu: w application typ `Registered`, w infra 201, w UI widoczny ekran skrzynki.
Nikt nie mówi, że zarejestrowany ≠ aktywny i że logowanie odmawia do kliknięcia linku.
Sam proces nie ma domu — jego fragmenty siedzą w cudzych plikach: `verify-email.feature` Rule 3
(„Registration automatically starts VERIFICATION") i `authenticate.feature` Rule 7 (poprawne dane
nie wystarczą przy niezweryfikowanym e-mailu).

**Kierunek (Roberta): trzy pliki — dwa atomowe + orkiestrator.** Analogia: atomowe use-case'y vs
orkiestrator. UWAGA do analogii: `security-application` NIE ma `src/main` — to wyłącznie runner
i glue testów bez HTTP; orkiestracja w kodzie (Authentication+ContinueAuthentication, MfaChain)
żyje w `security-system`. Dla specs analogia i tak działa: plik atomowy = kontrakt jednego
polecenia, plik procesu = sekwencja poleceń i kamienie milowe między nimi.

1. `register.feature` — zostaje kontraktem rejestracji (nie dopisywać do niego aktywacji).
2. `activation.feature` — to DZIŚ `verify-email.feature` (właściwy token aktywuje, śmieciowy
   odrzuca). Decyzja: nazwa od mechanizmu (verify-email) czy od skutku biznesowego (activation)?
   Reszta plików nazywa się od skutku → skłaniamy się do zmiany nazwy.
3. Plik procesu (nazwa robocza `register-and-activate.feature`; nie „e2e" — to technika, nie
   biznes; alternatywa `account-activation.feature` / onboarding): rejestracja → logowanie
   ODMAWIA (nieaktywne) → link z maila → logowanie PRZECHODZI. Nie powtarza reguł atomowych,
   tylko je sekwencjonuje. Rule 3 z verify-email i Rule 7 z authenticate to kandydaci do
   przeniesienia (decyzja o duplikacji otwarta).
   Warstwy: **infra + UI** (proces potrzebuje poczty; testowa skrzynka + `?verify=` już są).
   Application NIE — nie ma transportu i nie powinno go udawać. Tag `@ui`.

**Odrzucone po drodze.** Klasa `Fact` (wyrocznia stanu przez repozytoria: user istnieje, hash
zgadza się, aktywowany). W procesie zbędna: udane logowanie po kliknięciu dowodzi istnienia,
hasła i aktywacji naraz, bez zaglądania do bazy; odmowa przed kliknięciem dowodzi, że aktywacja
nie jest automatyczna. Sonda hashy na drucie = zły pomysł. `User` nie ma pola statusu —
aktywacja żyje w `EmailVerificationRepository.isVerified(email)`.

**Blokada techniczna — glue infra nie jest atomowe (to trzeba zrobić PRZED plikiem procesu):**
- każdy `RunHttp*Test` ładuje JEDEN pakiet glue; każda klasa kroków startuje własny
  `EmbeddedServer` w `@Before`;
- `@Given("a registered USER {string} with password {string}")` ma **13 kopii** w 13 pakietach
  (`the USER has AUTHENTICATED` — 6, `REGISTRATION is rejected` — 2, itd.);
- runner procesu ładujący pakiety registration + verification dostanie od Cucumbera
  DuplicateStepDefinitionException, a gdyby przeszedł — dwa serwery na scenariusz.
Refaktor: rozdzielić AKCJE (obiekty Javy: zarejestruj, odczytaj token ze skrzynki, zaloguj) od
KROKÓW (wiązania zdań); jeden wspólny kontekst (serwer, klient, ostatnia odpowiedź) dzielony przez
picocontainer (już w `bdd-test-starter`); wspólne kroki w jednym pakiecie `feature.common`.
Runner procesu = własna klasa z listą kilku pakietów glue, zero nowych akcji.
Ten refaktor broni się sam (spłaca 13 kopii) i można go zrobić niezależnie od decyzji o procesie.
**UI już tak działa**: cucumber-js ładuje `e2e/steps/*.mjs` naraz przez jeden World; kolizja
zdania = ambiguous → suita by padła; skoro zielona, kroki są tam współdzielone. Plik procesu
w UI zadziała bez przebudowy.

**Najmniejszy pierwszy krok, gdy Robert wróci:** sam TEKST pliku procesu, bez glue — sprawdzić,
czy sekwencja czyta się jako historia. Powiązane otwarte: password-policy przez 3 warstwy
(brak: kroki application dla `SetSetting` + panel admina w security-ui).

## Otwarte — nazwy pól po wprowadzeniu portu odczytu (2026-09-02, drobne)

Po `5656eb9` pole i argument nazywają się `passwordPolicy`, a mają typ `PasswordPolicyInForce`
— nazwa kłamie: trzymamy PYTAJĄCEGO o politykę, nie politykę. Do przemianowania na
`passwordPolicyInForce` w: `Register`, `ChangePassword`, `ResetPassword` (pole + argument
konstruktora) oraz `BeanFactory` (metoda fabryki i trzy argumenty wstrzyknięć).

Przy okazji zanotowane: asymetria `CanRegisterConfig` (wartość, stopień Restart) vs
`PasswordPolicyInForce` (port, stopień Live) jest CELOWA — jeśli domeny e-maila dostaną kiedyś
stopień Live, dostaną taki sam port i asymetria zniknie.

## Otwarte — po przeprojektowaniu drabinki (2026-09-05, przepisane 2026-09-06)

Stan po 2026-09-06: poziom live to JEDEN snapshot tabeli `security_settings`, brany przy starcie
(`@Context`, brak bazy wali boot) i po każdym zapisie admina — nigdy przy pytaniu, nigdy z zegara
(`SnapshotLiveConfigPort` w `shared/config`; TTL i property `security.settings.cache.ttl.seconds`
SKASOWANE tego samego dnia: TTL istniał tylko po to, żeby zauważać wiersze pisane obok API, czyli
legitymizował złamanie zasady Newmana), więc każdy klucz ma live/restart/rebuild i nie ma
„zamówień" na live per klucz.
Moduły `security-custom`, `security-roles`, `security-http` ROZPUSZCZONE w warstwach
(reguła właściciela: 3–5 warstw, nie wymyślać nowych): `RequireRole`/`RolesOf`/`BootstrapAdmins`
→ `security-system/roles`; `SetMinPasswordLength` + `MinLengthRepository` →
`security-system/passwordpolicy` (od 2026-09-06 wieczorem: `SetSetting` w `security-system/settings`); `Caller`/`RoleGuard`/`StepUpGuard`, `AdminPasswordPolicyController`,
`LadderedPasswordPolicy` (5 drabinek pod kluczami rekordów `password-config`, jedna polityka, bez
@Primary/@Secondary) → `security-infrastructure`; `SecuritySettingsTable` (Jdbc + InMemory) →
`security-infrastructure/persistence`. `password-application` w bibliotece SKASOWANY.
Zapis admina odświeża snapshot (`BeanFactory#minLengthRepository`, refresh czyta całą tabelę);
przy replikach (k3s, odłożone) unieważnienie musi pójść zdarzeniem między instancjami, nie zegarem. Nielegalny wiersz: warn RAZ per odmowa (nie per pytanie),
raport `rejected` niesie to, co wiersz trzymał (liczbę albo surowy tekst).

- **Zaakceptowana konsekwencja**: klucze BEZ endpointu admina (special chars, uppercase,
  lowercase, digit, brute-force, mfa, session) są w praktyce Restart — wiersz w bazie wchodzi
  dopiero przy następnym starcie albo przy zapisie admina pod innym kluczem; bramka drabinki nadal
  chroni przed wartością nielegalną. Powiedziane w `specs/password-policy.feature` (krok „written
  at the console before the last start") i w `application.yml`.
- **ZROBIONE 2026-09-06 (wieczór): generyczny zapis po kluczu.** `Configuration.liveOver` buduje
  katalog `LiveKey` (parser + bramka reguły, ta sama co przy odczycie); `SetSetting(key, text)` w
  `security-system/settings` (porty `SettingCatalog`, `SettingsRepository`) zastępuje
  `SetMinPasswordLength` + `MinLengthRepository`; `PUT /admin/settings/{key}` + `GET /admin/settings`
  (`AdminSettingsController`), `POST .../password/min-length` zostaje jako przypadek filmu 5.
  Spec `specs/settings.feature` (7 scenariuszy, glue `feature.settings`). Każdy nowy `liveOver`
  jest ustawialny bez linijki kodu. Decyzja właściciela: ryzyko „admin nadpisze każdy klucz"
  przyjęte świadomie — bramka = rola ADMIN + step-up; flaga per klucz „nie przez API" do
  dołożenia, gdy zajdzie potrzeba.
- **ADR do spisania** (właściciel): kontrakt drabinki + snapshot + dlaczego biblioteka nie zna
  drabinki. `SourceThrottle` → Live = te same trzy szczeble w `BeanFactory`, bez nowego modułu.

## Otwarte — wejścia i dokumentacja

- **Dokumentacja use case'ów — do usprawnienia (2026-09-04, do przemyślenia).** Punkt
  wyjścia: jest jeden `.feature` na klasę use case'u. Pomysł: opis spod `Feature:` przenieść
  do javadoca klasy — `{@link User}`, `{@link Email}` dają nawigację po klasach i zdejmują
  wersaliki (USER, EMAIL). Argumenty PRZECIW, spisane w rozmowie:
  - opis Feature ma innego czytelnika niż javadoc — `specs/README.md` czyni `.feature` jedynym
    źródłem prawdy dla trzech warstw; opis trafia do raportów Cucumbera (`report.html`,
    cucumber-js) i do warstwy UI, która nie ma żadnej klasy Javy; javadoc widzi tylko IDE;
  - wersaliki nie znikną — w `authenticate.feature` 27 z 78 linii ma CAPS i prawie wszystkie
    siedzą w krokach (`the USER AUTHENTICATES with the correct CREDENTIALS`), nie w opisie;
    CAPS to konwencja na słownik wspólny z biznesem (persony GUEST/USER/MODERATOR/ADMIN);
  - commit 10a3609 (2026-09-02) „no javadoc from Register down — the code is the document"
    wyciął 55 linii javadoców z rejestracji; javadoc na use case'ie to powrót do tego.
  Co już jest za darmo: plugin Cucumber w IntelliJ skacze krok → glue, glue → `Authenticate`
  / `User` przez Ctrl+B. Najtańszy most z `.feature` do klasy: jedna linia
  `# use case: Authenticate` pod `Feature:`. Otwarte pytanie: CO konkretnie w dokumentacji
  jest niewygodne (nawigacja? duplikacja opisu między `.feature` a kodem? raport?) — od tego
  zależy, czy odpowiedzią jest komentarz w `.feature`, generator (jak `build_documentation.py`
  w portalu), czy jednak javadoc.

- ~~UI jako 3. wejście~~ — ZROBIONE W CAŁOŚCI (2026-07-07, playbook S1, kroki 0–7): KAŻDY
  feature ze `specs/` zadeklarował wejścia tagiem — `@ui` jedzie przez realną przeglądarkę
  (cucumber-js+Playwright, `security-ui/run-e2e.sh`, selekcja `@ui and not @http-only`),
  `@http-only` to mechanika drutu (cookie/rotacja, introspekcja, taniec OAuth, logout —
  unieważnienie jedzie na cookie, którego cross-originowe dev UI nie trzyma; per-scenariusz
  także saga delete i federacyjny unlink). UI dorósł do speców: forgot/reset hasła,
  zmiana hasła i emaila w koncie (link `?change=`), lista sesji + „Sign out everywhere",
  danger zone ze step-upem FULL_CHAIN; sign-out przestał być kosmetyczny (POST /logout).
  Backdoory skrzynki: `/test/mailbox/{reset-token,notice}` obok istniejących. Konta w glue
  są scenariuszowo-unikalne (`support/account.mjs` — mutacje hasła/konta nie zatruwają
  innych feature'ów). **35 scenariuszy UI / 157 kroków zielone**; suita JVM 175 zielona.

## Porządki — ZAMKNIĘTE

- ~~Gałęzie remote-only, runda 2~~ — ZROBIONE (2026-07-07, zgoda usera): skasowane WSZYSTKIE
  gałęzie poza main w 6 repo. 4 były w pełni zmergowane (security: development/
  interactive-documentation/simplify-modules, test-starter/feature/mfa). 6 miało „stare"
  commity ale zbadane jako superseded: security feature/mfa (stare OTP MFA — main ma fazy
  A–H), restructure/smarter-factory (porzucone refaktory usuwające `AuthenticationRequest`,
  którego main używa), password/constraint/config/email feature/mfa (tytuł „Add maven
  wrapper" mylący — wrapper JUŻ na main; reszta to stare źródła + zacommitowane `target/`).
  Wszystkie repo mają teraz tylko main.

## Gotchas (operacyjne, warte pamięci)

- Po przeniesieniu pliku `.feature` zrób `mvn clean` — stara kopia w `target/test-classes`
  dubluje scenariusze.
- Runtime wymaga `org.yaml:snakeyaml`, inaczej Micronaut MILCZĄCO ignoruje `application*.yml`
  (w tym datasource!).
- `docker compose build` wymaga wcześniejszego `mvn package` (jar + `target/lib` budowane
  na hoście — build w kontenerze nie widzi security-libów z innych repo).
- Po micronaut-data POST bez `consumes` rejestruje trasę dwuznacznie (stąd `consumes=ALL`
  na `/refresh`).
