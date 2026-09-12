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

**19 feature'ów w `specs/`** (2026-09-12; było 13, gdy ta sekcja powstawała), każdy napędzany
czarną skrzynką przez HTTP (+ warstwa application dla części; `mfa`, `mfa-passkey` i
`federated-sign-in` nie mają runnera HTTP — TEST-2 w raporcie): Register, Authenticate (+brute-force; od 2026-07-02 wymaga zweryfikowanego
emaila — 403 `EMAIL_NOT_VERIFIED`, rejestracja auto-wysyła link), RefreshSession
(+reuse-detection), Authorize, Logout, Verify email (request+confirm), Reset hasła
(request+complete), Change password, Change email (z re-weryfikacją nowego adresu; potwierdzenie
oznacza nowy adres jako zweryfikowany), Delete account (RODO), List active sessions,
Revoke all sessions. Persystencja: Micronaut Data JDBC + Flyway + Testcontainers (in-memory,
gdy brak datasource). Deployment: `shared/docker-compose.identity.yml` w workspace-shared
(Postgres 5433 + serwis + Kafka), włączany przez compose obu produktów; wersja „Postgres + serwis"
z katalogu `docker-compose/` W TYM repo została SKASOWANA 2026-09-12 — nie miała Kafki, więc
uruchamiała serwis, który nie potrafił wysłać maila, a jej `.env` z hasłami leżał w publicznym repo. Maile: od 2026-07-02 **zdarzenia przez Kafkę**
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
- **ACC-1 (HIGH) — ZROBIONE 2026-09-12.** Anonimowy `POST /verify-email/request` odwerYfikowywał
  dowolne konto (jedno żądanie na ofiarę = 403 `EMAIL_NOT_VERIFIED` przy logowaniu; wtórnie
  otwierał przejęcie przez `FederatedSignIn.claimByEmail`). `RequestEmailVerification.execute`
  wychodzi od razu, gdy `repository.isVerified(email)` — bez tokenu, bez maila; endpoint nadal
  odpowiada tak samo dla każdego adresu (anty-enumeracja). Reguła w `specs/verify-email.feature`
  („Requesting VERIFICATION for an already verified EMAIL changes nothing"), glue HTTP + UI;
  wersja bez strażnika pada na 403 przy logowaniu właściciela. UWAGA: Background tego feature'a
  zmieniony na wariant „whose EMAIL is not verified yet" — w harnessie przeglądarkowym „a
  registered USER" kończy onboarding, więc reguła 1 musiała dostać własne zasianie.
- **AUTH-3 + ACC-4 — ZROBIONE 2026-09-12.** Sesje przeżywały zmianę adresu i po zarejestrowaniu
  zwolnionego adresu zaczynały mówić w imieniu NOWEGO właściciela. `ConfirmEmailChange` dostał
  `AuthorizationDataRepository` i woła `revokeAllSessions(stary)` zaraz po `updateEmail` (ta sama
  cena, którą płaci zmiana hasła). ACC-4: potwierdzenie zmiany w trakcie sagi usuwania jest
  odrzucane (`isPendingDeletion` → `InvalidToken`, jak wygasły bilet) — inaczej saga gubiła
  użytkownika pod nowym adresem. `sessions` DOŁĄCZYŁY do rejestru w `AddressKeyedStoresTest`
  (kategoria „nie idzie za kontem"), akapit „deliberately NOT in the registry" skasowany.
  Reguła w `change-email.feature` (@http-only); bez poprawki pada, pokazując `/me` odpowiadające
  starym adresem po przeprowadzce. DOM-2 (kontrakt `updateEmail` przy zajętym adresie) NIE ruszony
  — zmienia kontrakt portu i kształt wyniku use-case'u, decyzja właściciela.
- **HTTP-1 + HTTP-2 — ZROBIONE 2026-09-12.** Za zaufanym proxy źródłem był LEWY element
  `X-Forwarded-For`, czyli ten, który pisze klient (proxy DOKLEJA) — klucz throttle'ów i lockoutu
  do wyboru przez atakującego (albo podstawiany ofierze). `ClientIpResolver` chodzi teraz od
  PRAWEJ, pomija własne proxy i bierze pierwszy nie-nasz; element, który nie jest adresem
  (`unknown`), leci na peera zamiast 500. `TrustedProxyHttpTest` (throttle rejestracji jako
  przyrząd: „czy to samo źródło?"); na starym kodzie padają 2 z 4 przypadków.
  **UWAGA do PLAN-P12 K1 (portal):** `security.trusted-proxies` porównuje DOKŁADNE adresy — CIDR
  nie pasuje do niczego. K1 musi wymienić adresy podów ingressu, nie sieć podów. Zapisane też w
  javadocu klasy.
- **AUTH-2 + ATK-4 — ZROBIONE 2026-09-12.** Dwa nowe okna na źródło w `BeanFactory`:
  `@Named("authentication")` (domyślnie 30/15 min, WSPÓLNE dla `/authenticate` i
  `/authenticate/factor` — kto ma hasło, otwierał bilety bez końca, każdy wart 5 strzałów w drugi
  czynnik i jeden mail do ofiary) oraz `@Named("change-password")` (10/15 min — `/account/password`
  był wyrocznią Argon2 dla skradzionego tokenu, a trafienie = przejęcie, bo zmiana kasuje sesje).
  Oba 0 w profilu `test`, oba udokumentowane w `application.yml` razem z czterema starszymi i
  `trusted-proxies` (połowa HTTP-18: dokumentacja; migracja kluczy na drabinkę nadal otwarta).
  Testy: `AuthThrottleHttpTest`, `ChangePasswordThrottleHttpTest`. Docs zrównane: change-password
  NIE jest pod step-upem (`docs/mfa-design.md`, `docs/opus-playbook.md`).
  NIE robione (decyzja właściciela): `Source` w `PendingAuthentication` i liczenie złych proofów
  przez `_UpdateBruteForceRecords` — to zmiana kształtu use-case'u.
- **DOM-1 — ZROBIONE 2026-09-12.** User-Agent dłuższy niż 400 znaków wywracał INSERT (22001):
  500 z SQL-em w ciele i — co gorsza — ŻADNEGO wiersza porażki, więc blokada nigdy nie wskakiwała
  i hasło można było zgadywać bez końca. `JdbcRejectedAuthenticationRepository` przycina nagłówek
  do szerokości kolumny (`USER_AGENT_COLUMN_WIDTH = 400`, V9) — `Source` nietknięty, bo to adapter
  zna kształt tabeli. Przypadek w `JdbcAdaptersTest` (Testcontainers, Postgres 18); bez przycięcia
  pada z „value too long for type character varying(400)".
- **OPS-1 — ZROBIONE 2026-09-12.** Auto-merge Dependabota bramkował po SAMEJ NAZWIE gałęzi: PR z
  forka nazwany `dependabot/*/patches-*` wjeżdżał na main bez udziału człowieka (repo publiczne,
  brak branch protection, job działa tokenem repo bazowego). Do `if` doszły `actor.login ==
  'dependabot[bot]'` i `head_repository.full_name == github.repository`; krok dodatkowo pyta API
  (`--author app/dependabot`, `gh pr view --json author,isCrossRepository`) i odmawia, gdy PR nie
  jest Dependabota albo jest z forka.
- **UI-1, UI-2, UI-3, UI-4, UI-5, UI-7 — ZROBIONE 2026-09-12.** Karta żyje dłużej niż sesja:
  `clearAccountState()` czyści kody odzyskiwania (pokazywane raz, jawnie) i cały stan paneli —
  wołane przy wylogowaniu I na wejściu w sesję; `signOut` czyści też adres i hasło z formularza,
  `signIn` kasuje hasło ze stanu na obu gałęziach. 403 rozpoznawany po CIELE
  (`STEP_UP_REQUIRED`), nie po samym statusie — MODERATOR pod progiem MFA nie kręci się już w
  pętli elewacji. 401 na wywołaniu z tokenem = „sesja wygasła", a nie „złe hasło". Czynnikowa
  połowa step-upu zna `nextFactor`: dla `WEBAUTHN` prosi authenticator (`assertPasskey`) zamiast
  renderować pole na kod — konto tylko z passkeyem mogło dotąd nie zrobić NICZEGO za step-upem.
  Wszystkie handlery lecą przez `run()`, dwa fetch-e z useEffect dostały `.catch`.
  Testy: `security-ui/src/App.tab.test.tsx` (6 przypadków, wszystkie padają na starym kodzie);
  vitest chodzi w CI (job `ui`). UWAGA: vitest wymaga Node 22 (lokalnie: nvm).
- **ACC-2 — ZROBIONE 2026-09-12.** Polityka e-maili (blocked/disposable/company) obowiązywała
  TYLKO przy rejestracji, więc zamknięty sklep był otwarty dla każdego, kogo raz wpuścił: zmiana
  adresu wyprowadzała konto razem z rolami, czynnikami i linkami federacyjnymi. `RequestEmailChange`
  dostał `CanRegisterConfig` i pyta pierwszy (`_NewEmailVerdict`, krok pakietowy wg ADR 0002),
  nowy wynik `Rejected(codes, policy)`, `EmailChangeController` → 422 w kształcie `/register`
  (`SecurityController.emailErrors`). Test jednostkowy + reguła w `change-email.feature`
  (@http-only — compose nie konfiguruje żadnej listy, więc przeglądarkowa warstwa jej nie uruchomi;
  glue HTTP startuje z `security.email.disposable.domains=mailinator.com`).
- **Obsługa błędów brzegowych (HTTP-5 z rodziną, HTTP-8, HTTP-9, HTTP-4, HTTP-16, WIRE-3, WIRE-4)
  — ZROBIONE 2026-09-12.** Moduł nie miał ŻADNEGO `ExceptionHandler`, więc zdanie value objectu
  wracało do klienta jako 500. Teraz: `EdgeErrors` (IllegalArgumentException → 400 stały kształt,
  `NotAuthenticatedException` → 401, prawdziwa przyczyna do logu), puste/białe pola odrzucane w
  trzech adapterach (bilety MFA i step-upu, hasła), puste hasło w step-upie = brak hasła (401, jak
  dotąd), `/me/**` w filtrze (`/me/` szło NIEfiltrowane), pusty cookie `refresh_token` = brak
  cookie, adres z literówki w ścieżce admina parsowany PRZED strażnikiem step-upu (jednorazowa
  elewacja nie przepada), `UNKNOWN_ROLE` podaje listę ról zamiast nazwy klasy enuma, allow-lista
  return-URL normalizowana do „/" (inaczej `http://app.example` wpuszczało
  `http://app.example.evil.net/` z tokenem we fragmencie), a bzdura od providera OAuth to
  `#oauthError`, nie 500 na origin security. `EdgeErrorsHttpTest` (5 przypadków, wszystkie padają
  na starym kodzie — z dokładnie tymi 500-kami z raportu) + przypadek WIRE-3 w `OauthFlowHttpTest`.
- **Wyścigi (AUTH-1, AUTH-5/MFA-6, DB-6, DB-17, ACC-11, DB-3) — ZROBIONE 2026-09-12.**
  AUTH-1: strażnik brute-force był check-then-act — 20 równoległych prób z jednego adresu
  przechodziło przy limicie 3, a próba, która w końcu trafiła limit, KASOWAŁA nadmiarowe wiersze,
  więc sufit per źródło też ich nie widział. Blokada doradcza `pg_advisory_xact_lock(hashtext(ip))`
  w transakcji żądania. WAŻNE: raport kazał ją wziąć w `countFailuresOnAccount`, ale to ZA PÓŹNO —
  strażnik najpierw pyta o istniejącą blokadę; blokada jest brana także w
  `JdbcAuthenticationBlockRepository.findBy` (pierwsze pytanie strażnika). `BruteForceRaceTest`:
  bez tego przechodzi 10 z 20, z tym ≤ 3.
  AUTH-5: licznik prób przy drugim czynniku był read-modify-write na trzy wywołania store'a →
  20 proofów naraz zużywało jedną próbę. Porty `PendingAuthenticationStore` i `StepUpStore` mają
  `update(ticket, fn)` (domyślnie stara sekwencja, atomowo w adapterach in-memory = produkcja);
  `PendingStoreAtomicityTest` pokazuje -6 zamiast -15 bez poprawki.
  DB-6/DB-17/ACC-11: `ON CONFLICT` zamiast delete+save / exists+save / check+insert (blokada źródła,
  ustawienie admina, start sagi usuwania — drugi „skasuj konto" dostawał 500 zamiast dołączyć).
  DB-3: `consumeReset`/`confirmChange`/`completeVerification` — decyduje ZAPIS (warunkowy DELETE/
  UPDATE i liczba wierszy), nie odczyt; dwie prezentacje tego samego linku nie mogą już obie wygrać.
- **Config na starcie (WIRE-5/CFG-1, CFG-3, CFG-4) — ZROBIONE 2026-09-12.** Wartości ustalone na
  całe życie serwisu czytane są teraz PRZY STARCIE (`@Context`): polityka e-maili (javadoc od
  dawna to obiecywał, kod nie — `company.domains=acme` wstawał, a wywracała się pierwsza
  rejestracja), bootstrap-admini i ustawienia providerów OAuth (provider USERINFO bez `userinfo-url`
  wstawał, a `GET /oauth/providers` dawało 500 = zero przycisków social w UI).
  CFG-3: sufit dla progu MFA — próg wyższy niż liczba czynników, które deployment OFERUJE, wywala
  boot z nazwą klucza (`min.factors.admin: 6` zamykał każdego ADMINA poza `/admin/**` na zawsze,
  łącznie z tym, kto miałby liczbę cofnąć). CFG-4: dwie reguły międzypolowe `BruteForceConfig` i
  zakres `MaxFailuresPerSource` mają wreszcie testy. `ConfigAtBootTest` — 3 z 5 przypadków padają
  na starym kodzie (czwarty to nowy sufit, piąty pilnuje, że pusty config nadal wstaje).
- **Przegląd dokumentacji (OPS-3..OPS-11, DB-16, TEST-4) — ZROBIONE 2026-09-12.**
  `todo.md`: sekcja „Otwarte — pilne" opisywała pracę, która OD MIESIĄCA jest na main (f94c99d,
  a8ef840, 163755f) — zamknięta ze sprostowaniem; 13 → 19 feature'ów; akapit o odpinaniu tożsamości
  federacyjnych przy zmianie adresu (dziś PRZEPINANIE); „klucze bez endpointu admina" (dziś każdy
  `liveOver` idzie przez `PUT /admin/settings/{key}`).
  `Readme.md`: przepis build clonował 5 z 8 repo (czysty `~/.m2` = brak buildu); „13 specs",
  „UI not built yet", „in-memory adapters" — wszystko z lipca.
  `Documentation.md`: nagłówek mówi wprost, że to zdjęcie jednego runu z 2026-07-02, a nie żywa
  dokumentacja. `docs/mfa-design.md`: elewacja NIE jest kolumną w wierszu sesji i nie ma
  `/account/step-up/start`. `docs/opus-playbook.md`: use case'y są w `security-system`
  (`security-application` nie ma `src/main`); S5 zamknięte. `security-ui/README.md`: tagi, 39
  scenariuszy, vitest w CI. DB-16: trzy komentarze w persystencji (V10→V18, „counts by IP alone",
  „snapshot once per TTL"). TEST-4: świadek w CI obejmuje wszystkie 4 weryfikacje paktów i 5 suit
  na Testcontainers (`disabledWithoutDocker` = ciche zielone), `SilentlySkippedPactTest` zna
  wszystkich czterech konsumentów.
  NIE ruszone celowo: komentarze w V22/V25 (dryf checksumy Flyway — DB-4).
- **HTTP-3 + ACC-7 + AUTH-4 — ZROBIONE 2026-09-12.** `ProfileGuard` wymaga DOKŁADNIE jednego
  profilu z trójki: para `prod,test` przechodziła, a `test` niesie anonimowe `/test/clock`
  i `/test/mailbox` — czyli skrzynkę z linkami weryfikacyjnymi na produkcji. `/me` i claim `roles`
  w JWT idą przez `RequireRole.rolesInForce`: bootstrap-admin miał `roles=[USER]` wszędzie poza
  bramką `/admin/**`, więc każdy konsument bramkujący po tokenie nie zgadzał się z serwisem, który
  ten token wystawił (przypadek w `JwtAccessTokenHttpTest`, pada na starym kodzie). `_VerifyCredentials`
  liczy Argon2 także dla NIEZNANEGO adresu (hash policzony raz przy budowie kroku): dotąd nieznany
  adres wracał w milisekundę, a znany kosztował pełny hash — enumeracja kont z zegara na endpoincie,
  który słowami odmawia enumeracji. Stary test PINOWAŁ tę asymetrię (`verifyNoInteractions`).
- **MFA-2 + MFA-3 — ZROBIONE 2026-09-12.** Kod TOTP działał przez całe okno ±1 krok, więc kto go
  zobaczył (relay phishingowy, zrzut ekranu, ramię), miał jeszcze do 90 s, żeby wejść OBOK
  właściciela. Nowy port `SpentTotpSteps` (+ `InMemorySpentTotpSteps`): krok jest do wydania RAZ,
  `compute` zamiast get-then-put, wymiatanie po godzinie. Sweeper enrolmentów wywalał się NPE na
  pierwszym oczekującym TOTP (`challenge()` = null) i zabijał zamiatanie DLA WSZYSTKICH —
  porzucone sekrety TOTP żyły wiecznie i dawały się potwierdzić; każdy wpis ma teraz własny termin
  (`security.mfa.enrolment.ttl-minutes`, domyślnie 15). `EnrolmentSweeperTest` na starym wyrażeniu
  rzuca dokładnie tym NPE; prawo `StoresWithADeadlineEvictThemTest` samo złapało nowy store i
  kazało go sklasyfikować (grepuje istnienie sweepera — dlatego NPE w środku przeszedł niezauważony).
- **ATK-6 + WIRE-6 — ZROBIONE 2026-09-12.** `state` w OAuth był kluczem po stronie serwera i NICZYM
  więcej, więc link callbacku działał jak bilet na okaziciela: atakujący zaczynał taniec, podsuwał
  link ofierze, a przeglądarka ofiary dostawała sesję TOŻSAMOŚCI ATAKUJĄCEGO (session fixation).
  `/oauth/{provider}/start` ustawia teraz krótkie ciasteczko `oauth_state` (HttpOnly, SameSite=Lax,
  ścieżka `/oauth`, 10 min), a callback wymaga zgodności — bez tego 400 i ŻADEN flow nie jest
  konsumowany. Testy niosą ciasteczko jak przeglądarka; nowy przypadek „callback to nie bilet".
  WIRE-6: kody odzyskiwania miały nieosolony SHA-256 (2^49 kandydatów = godziny na jednym GPU, a
  każdy kod zastępuje CAŁY łańcuch). Nowy port `RecoveryCodeHasher` + `PepperedRecoveryCodeHasher`
  (HMAC-SHA256 pod pieprzem `security.mfa.recovery.pepper`) — kluczowany, nie solony, bo kod wydaje
  się przez WYSZUKANIE hasha. Pod profilem `prod` brak pieprzu wywala boot po nazwie klucza.
  **UWAGA MIGRACYJNA: kody wydane wcześniej (stary SHA-256) przestają pasować — użytkownicy muszą
  wygenerować nowe.** To samo przy każdej zmianie pieprzu.
- **Biblioteka `account-closure` — 2026-09-12.** Słownik zamknięcia konta (7 nazw komunikatów +
  SELF/ADMIN z asymetrycznym odczytem) był rozpisany w PIĘCIU miejscach: enum w security, `final
  class RequestedBy` w offboardingu i `private static final String BY_ADMIN` w memes/comments/
  collections. Nowe repo `shared/account-closure` (czysta Java, zero zależności), wpięte we
  wszystkie pięć serwisów; tu trzymane W INFRASTRUKTURZE (to słownik DRUTU), domena nietknięta —
  `DeletionInitiator` zostaje, a `ClosureVocabularyTest` pilnuje, że obie strony mówią to samo.
  **DO ZROBIENIA PRZEZ ROBERTA: repo nie istnieje na GitHubie** — trzeba je założyć i wypchnąć,
  zanim CI któregokolwiek z pięciu serwisów zobaczy zielone (checkout + install już dopisane).
- **LOW, paczka 1 (MFA-11, MFA-12, MFA-15, WIRE-2, WIRE-9, WIRE-12) — ZROBIONE 2026-09-12.**
  `WebauthnFactor` sprawdza WRESZCIE `Challenge.expiresAt` (TTL był konfigurowalny, udokumentowany
  i martwy) oraz porównuje `credentialId` asercji z zapisanym; TOTP porównywany stałoczasowo
  (higiena, nie dziura — 5 prób na bilet). `OidcClient`: `alg=none` odrzucany, a alg asymetryczny
  przyjmowany tylko dla providera z zadeklarowanym `issuer` (inaczej „nieweryfikowalny" przechodził
  jako zaufany). JWKS ma `Cache-Control: public, max-age=3600` (godzina = okno nakładki kluczy).
  `backTo` nie dokleja drugiego `#` — return-URL z własnym fragmentem gubił i stan appki, i token.
  NIE zrobione świadomie: MFA-4 (brak limitu prób przy potwierdzaniu enrolmentu) — wymaga pola
  w `PendingEnrolment`, czyli zmiany kształtu portu; okno i tak ogranicza TTL 15 min + elewacja.
- **LOW, paczka 2 (AUTH-9, AUTH-12, DB-5, DB-7, DB-11) — ZROBIONE 2026-09-12.** `SourceThrottle`:
  zamiatanie wolnych okien chodziło NA ŚCIEŻCE ŻĄDANIA przy każdym wywołaniu powyżej progu, a w
  obrębie jednego okna nie ma czego zwolnić — czyli O(n) na żądanie, które nic nie daje; teraz raz
  na przyrost + twardy sufit 100k (najstarsze okna lecą pierwsze). DB-5: `TimeZone.setDefault(UTC)`
  w `App.main` — `Instant` idzie do JDBC przez `java.sql.Timestamp`, czyli przez strefę JVM-a, więc
  serwis z IDE w Europe/Warsaw czytał sagi ze stacku o dwie godziny obok (a tak właśnie pracujemy).
  DB-7: `V26` dodaje indeksy `sessions(email)` i `sessions(refresh_token_expiration)` — bez nich
  każde „wyloguj wszędzie", lista sesji i reaper skanowały całą tabelę (i to brak indeksu na email
  robił z dwóch blokujących zapytań różne plany → zakleszczenie opisane przy `lockFamily`).
  DB-11: drain outboxu bierze partię (`security.outbox.drain-batch`, 500), nie CAŁEGO zaległego
  backlogu co sekundę. AUTH-12: javadoc obiecywał nieprzewidywalną długość blokady, którą
  `Retry-After` podaje co do sekundy — teraz mówi, po co naprawdę jest losowanie.
- **LOW, paczka 3 — UI (UI-6, UI-8, UI-17, UI-18) — ZROBIONE 2026-09-12.** Panel step-upu mówił
  „Wrong code." także na TOO_MANY_ATTEMPTS i wygasły bilet — czyli odsyłał człowieka do pola, które
  już nigdy nie zadziała; teraz rozróżnia i zamyka panel, gdy nie ma czego wpisywać. Podwójny klik
  liczył się jako DWIE nieudane próby w liczniku brute-force (kto ma wolne łącze, blokował się w
  połowie limitu) — strażnik `once()` na ref (stan re-renderuje się o rundę za późno); test w
  `App.tab.test.tsx` pokazuje 3 żądania bez poprawki. Skasowany martwy `src/index.html` z
  `<app-root>` po Angularze i `.angular/` z `.gitignore`. `SECURITY` czyta teraz kolejno
  `window.SECURITY_URL` (runtime, tak robi harness i tak może robić deployment przez `/ui-config.js`),
  `VITE_SECURITY_URL` (build) i dopiero potem compose'owy localhost:8080 — produkcyjny bundle
  wskazywał na localhost i nikt tego nie widział tylko dlatego, że `dist/` nikt jeszcze nie serwuje.
- **LOW, paczka 4 — domena (DOM-3, DOM-5, DOM-7) — ZROBIONE 2026-09-12.** `AbstractToken.toString`
  zwracał SUROWY sekret — pierwsza linijka logu, która wstawi token do napisu, wynosi żywy
  credential do systemu z własną retencją; teraz zwraca nazwę klasy. `equals` był międzytypowy
  (AccessToken == RefreshToken o tej samej wartości) — teraz typ jest połową tożsamości tokenu,
  `hashCode` też. `TokenSecrecyTest` w domenie. DOM-3: `ClientIpResolver` kanonizuje adres (ucina
  zone id `%eth0` — to nazwa interfejsu TEJ maszyny, nie dzwoniącego) i odrzuca kandydata dłuższego
  niż kolumna `VARCHAR(64)`: źródła, którego nie da się ZAPISAĆ, nie da się też ograniczyć.
- **LOW, paczka 5 — testy, które nic nie twierdziły (TEST-8, TEST-9, TEST-14) — ZROBIONE 2026-09-12.**
  `MalformedEmailHttpTest` sprawdzał tylko „< 500" — 301 na stronę logowania albo 200, które po
  cichu ZROBIŁO rzecz, też by przeszły; teraz: drzwi odmawiające dają 4xx, dwoje cichych drzwi
  (`/verify-email/request`, `/reset-password/request`) dają dokładnie to samo 202 co dla obcego
  adresu, i żadne nie cytuje wnętrza serwisu. Scenariusz „not a twin" twierdził wyłącznie, że ktoś
  jest zalogowany — asercja o bliźniaku siedziała w kroku INNEGO przykładu i sama robiła drugie
  logowanie, żeby mieć co porównać; teraz ma własne „the ACCOUNT ... is the one that already
  existed". Scenariusz enumeracji przy zmianie adresu nie sprawdzał, czy do zajętego adresu NIE
  poszedł link (porównanie do stanu sprzed żądania, bo adres bywa zasiany rejestracją).
- **DOM-2 — ZROBIONE 2026-09-12 (decyzja Roberta: pełna naprawa).** Port `UserRepository.updateEmail`
  ma wreszcie kontrakt na zajęty adres (jak `save`): rzuca `EmailAlreadyTakenException`, NIGDY nie
  nadpisuje. JDBC tłumaczy 23505 (było: 500 i ten sam link dawał 500 aż do wygaśnięcia), in-memory
  sprawdza zajętość po formie znormalizowanej (było: CICHE nadpisanie cudzego konta).
  `ConfirmEmailChange` pyta przed ruszeniem czegokolwiek i łapie wyścig → nowy wynik
  `EmailTaken`, HTTP 409 `EMAIL_TAKEN`, UI mówi „adres zajęty, poproś o zmianę na inny".
  Reguła w `change-email.feature` + testy obu adapterów. PRZY OKAZJI: glue confirm-u zapamiętuje
  token W MOMENCIE WYSŁANIA — skrzynka pamięta tylko ostatni, a w tym scenariuszu adres dostaje
  własny link rejestracyjny.
- **DB-8 — ZROBIONE 2026-09-12 (decyzja Roberta: dla wszystkich domen + raport kolizji).**
  W bibliotece `email`: `LocalPart.normalize` sprowadza część lokalną do małych liter dla KAŻDEJ
  domeny (reguły providerów — kropki gmaila, `+tagi`, sufiksy yahoo — bez zmian, bo to twierdzenia
  providera o WŁASNEJ przestrzeni adresów). W security: `UserRepository.findBy` szuka po formie
  ZNORMALIZOWANEJ (dotąd rejestracja odmawiała duplikatu, a logowanie tego samego adresu inną
  wielkością liter mówiło „złe hasło"), a `_VerifyCredentials` zwraca ZAPISANĄ pisownię, więc
  wszystko dalej (weryfikacja adresu, czynniki, sesja, token) trafia w to samo konto.
  Migracja `V27` przenormalizowuje istniejące wiersze i **ODMAWIA**, jeśli powstałyby kolizje —
  wtedy trzeba najpierw `docs/db8-case-collisions.sql` i decyzja człowieka, które konto zostaje
  (migracja nie może tego wybrać za kogoś). `AddressCaseHttpTest` pada na starej regule.
- **LOW, paczka 6 — build/ops/kontrakty (OPS-13, OPS-14, OPS-17, CFG-9, TEST-10, DOM-10, DOM-11)
  — ZROBIONE 2026-09-12.** Skasowane: `set-security-domain-version.sh` (ustawiał property, którego
  nie ma, a per-modułowe wersjonowanie rozjechałoby reaktor — w estacie wszystko jest
  1.0.0-SNAPSHOT) i katalog `docker-compose/` (sierota bez Kafki, z `.env` i hasłami w PUBLICZNYM
  repo; prawdziwy stack to `shared/docker-compose.identity.yml`). Pom: wywalona whitelista po
  rozpuszczonym module `custom-min-password-length`, procesor lomboka, którego nikt nie używa,
  i zakomentowany import `junit-bom`; pakty mają JEDNĄ wersję (`${pact.version}` — `provider` był
  4.7.3 obok 4.7.5). Sprostowane: `application.yml` twierdził, że KAŻDY klucz ma trzy szczeble
  (brute-force/mfa/session/step-up mają dwa), komentarz `RunCucumberTest` mówił o „trzech
  feature'ach" (jest pięć z dziewiętnastu), javadoc `FailuresCount` opisywał tylko sufit per adres,
  a port `AuthenticationBlockRepository.create` nie mówił, że to upsert.
- **LOW, paczka 7 — konfiguracja (CFG-2, CFG-5, CFG-7, CFG-8, CFG-11, CFG-12, CFG-13)
  — ZROBIONE 2026-09-12.** `CodeTtlMinutes` i `CodeMaxAttempts` mają wreszcie SUFIT (kod ważny
  tydzień to hasło leżące w skrzynce; sto prób na bilet to nie drugi czynnik) — zakresy opisane
  w `MfaValueRangesTest` razem z pozostałymi pięcioma VO MFA, które nie miały żadnego testu.
  `OauthProviderSettings`: URL-e muszą być ABSOLUTNE http(s) (`idp:8091/token` wstawał i wywracał
  callback 500-ką), a knobki USERINFO na providerze ID_TOKEN są ODRZUCANE zamiast cicho ignorowane;
  pierwszy test tej klasy (`OauthProviderSettingsRulesTest`). `docs/oauth-providers.md` wymienia
  `issuer` we wspólnych kluczach (kod sprawdzał `iss`, dokumentacja o kluczu milczała).
  `StepUpRequirement.parse` SKASOWANY — drabinka parsuje enumy generycznie (`Parse.forType`),
  a ten drugi parser miał tylko własny test i zero wywołań w main.
- **LOW, paczka 8 — brzeg HTTP (HTTP-10, HTTP-14, HTTP-15, HTTP-17, HTTP-21) — ZROBIONE 2026-09-12.**
  Jeden kształt odmowy: `Refusal` — `{"status": KOD}` wszędzie, `error` zostaje OBOK tam, gdzie był
  (addytywnie wg ADR 0004), a bezciałowe 401 dostały ciało. `X-Correlation-Id` od klienta jest
  przycinany do 64 znaków i kształtu id (echo + log w każdej linii żądania = kilobajt cudzego tekstu
  w każdym agregatorze). Jednorazowa elewacja nie jest już wydawana PRZED walidacją: typ czynnika i
  nowy adres czytane są przed strażnikiem (literówka kosztowała cały łańcuch step-upu). Usuwanie
  czynnika: podłoga odpowiada NAJPIERW (409 bez wydawania elewacji) i PONOWNIE w transakcji, która
  usuwa — dwa równoległe usunięcia czytały „jeden ponad podłogą" i oba usuwały. `RefreshCookies`
  mówi wprost, czego SameSite NIE obejmuje (inny port na localhoście i sąsiedni subdomain to ta sama
  witryna) i że uczciwą naprawą byłby double-submit, bo ostrzejszej flagi nie ma.
- Otwarte z raportu: 27 MEDIUM/101 LOW poza powyższymi paczkami (m.in. ATK-6 CSRF OAuth, AUTH-4
  timing, MFA-2 replay TOTP, MFA-3 sweeper, WIRE-6 kody odzyskiwania na SHA-256, HTTP-3 prod+test,
  DB-5 strefy czasowe, OPS-13/14/17) + pozycje kształtu domeny do DECYZJI WŁAŚCICIELA:
  DOM-2 (kontrakt `updateEmail`), DOM-9 (`UserRegistration` martwy), DOM-12 (nazwy),
  DB-8 (`NormalizedEmail` tylko dla 4 domen), `Source` w `PendingAuthentication` (AUTH-2).
  throttle'y (AUTH-2, ATK-4) → DOM-1 → OPS-1 → UI-1/UI-2 → ACC-2 → obsługa błędów brzegowych →
  wyścigi → config na starcie → przegląd dokumentacji.

## ~~Otwarte — pilne (2026-08-08)~~ — ZAMKNIĘTE, sekcja była NIEAKTUALNA (sprostowane 2026-09-12)

Ta sekcja przez miesiąc twierdziła, że wygaszanie linków zmiany adresu i czynnikowa połowa
step-upu w UI „czekają na gałęzi `wip-email-change-expiry`". Git mówi co innego: `f94c99d`
(przywrócenie paczki), `a8ef840` (UI dokańcza czynnikową połowę step-upu — trzy akcje, jedna
droga) i `163755f` (wygaszanie linków wraca na main z dokończonym UI) SĄ na main. Gałąź robocza
została w tyle i nic z niej nie zostało do przeniesienia.

Co z tamtej listy jest dziś prawdą: nic. Czynnikowa połowa step-upu w UI ma od 2026-09-12 także
gałąź passkeya (UI-5) i sześć testów w `security-ui/src/App.tab.test.tsx`.

Zostaje jedna rzecz warta pamięci, bo to pułapka harnessu, a nie dług: browser e2e **nie chodzi
w CI** (potrzebuje całego stosu — `run-e2e.sh`), więc reguła, która żyje tylko w warstwie
przeglądarkowej, nie jest bramką. Wiążący dowód = warstwa HTTP/JVM.

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
  ~~Odświeżanie linku federacyjnego przy change-email~~ — ZROBIONE (2026-07-07, playbook S2),
  ale UWAGA: decyzja została później ODWRÓCONA i ten akapit był nieaktualny do 2026-09-12.
  Dziś potwierdzenie zmiany adresu PRZEPINA tożsamości federacyjne na nowy adres
  (`FederatedIdentityRepository.relinkAll`), bo link jest kluczowany trwałym `subject` providera —
  odpięcie osierociłoby tożsamość (provider dalej podaje swój stary adres, więc auto-link nigdy by
  nie trafił w przeniesione konto). Prawo ruchu jest spisane w `AddressKeyedStoresTest`. Reguła w change-email.feature (HTTP glue), unit w
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

- **~~Zaakceptowana konsekwencja: klucze BEZ endpointu admina~~ — NIEAKTUALNE od 2026-09-06**
  (sprostowane 2026-09-12). Każdy klucz zadeklarowany jako `liveOver` jest ustawialny przez
  `PUT /admin/settings/{key}` — dotyczy to WSZYSTKICH pięciu reguł hasła. Restartem pozostają
  klucze `boundOver` (brute-force, mfa, session, step-up): tam wiersz w bazie wchodzi dopiero przy
  następnym starcie, a bramka drabinki chroni przed wartością nielegalną. Tak też mówi
  `specs/password-policy.feature` (krok „written at the console before the last start").
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
