# Collective Allure Test Report & Documentation

> **What this file is, and what it is not** (2026-09-12). It is a SNAPSHOT of an Allure run across
> the whole workspace, generated on the date below and not regenerated since — so the numbers below
> are a photograph of that morning, not the state of this repository today, and they cover other
> services as well as this one. The README used to promise it as "detailed documentation of the
> domain, config and system layers"; the living version of that promise is the code and the tests
> themselves: `specs/*.feature` for behaviour, the value objects in `security-domain` and
> `security-config` for the rules, and `docs/` for the designs. Regenerate this file with
> `shared/aggregate_allure.py` after a full run if you want a fresh photograph.

Generated on: 2026-07-02 07:37:33

## 📊 Execution Summary

| Module | Total | Passed | Failed | Broken | Skipped | Duration |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| adjustable-clock | 16 | 16 | 0 | 0 | 0 | 145ms |
| email/email-domain | 13 | 13 | 0 | 0 | 0 | 152ms |
| email/email-security/email-security-config | 1 | 1 | 0 | 0 | 0 | 91ms |
| email/email-security/email-security-system | 28 | 28 | 0 | 0 | 0 | 177ms |
| infrastructure-micronaut-clock | 12 | 12 | 0 | 0 | 0 | 2.14s |
| microservice-memes/memes-application | 9 | 9 | 0 | 0 | 0 | 85ms |
| microservice-memes/memes-config | 2 | 2 | 0 | 0 | 0 | 23ms |
| microservice-memes/memes-image | 2 | 2 | 0 | 0 | 0 | 198ms |
| microservice-memes/memes-infrastructure | 5 | 5 | 0 | 0 | 0 | 1.48s |
| microservice-security/security-config | 13 | 13 | 0 | 0 | 0 | 166ms |
| microservice-security/security-system | 39 | 39 | 0 | 0 | 0 | 1.06s |
| password/hash-algorithms/argon2 | 2 | 2 | 0 | 0 | 0 | 637ms |
| password/hash-algorithms/argon2-config | 7 | 7 | 0 | 0 | 0 | 140ms |
| password/password-domain | 1 | 1 | 0 | 0 | 0 | 171ms |
| password/password-security/password-security-config | 9 | 9 | 0 | 0 | 0 | 169ms |
| password/password-security/password-security-system | 19 | 19 | 0 | 0 | 0 | 193ms |
| **TOTAL** | **178** | **178** | **0** | **0** | **0** | **7.02s** |

## 📝 Test Documentation (Behaviors)

This section describes the verified system behaviors based on passing tests.

### Epic: Config

#### Feature: Image limits

- **keeps a positive maximum dimension**
- **rejects a non-positive maximum dimension**

### Epic: Email

#### Feature: Config

##### Story: CanRegister

- **default config → all domain wrappers are absent**
  - *Parameters:*
    - default: `CanRegisterConfig[blockedDomains=null, disposableDomains=null, companyDomains=null]`

#### Feature: Constraints

##### Story: BlockedDomain (for instance: "junk.org")

- **accepts "user@example.com"**
- **error code is DOMAIN_BLOCKED**
- **rejects "admin@junk.org" (domain is on the blocked list)**

##### Story: CompanyDomain (for instance: "corp.org")

- **accepts "user@corp.org"**
- **error code is NOT_A_COMPANY_DOMAIN**
- **rejects "somebody@public-vendor.com" (domain is not on the company list)**

##### Story: DisposableEmail (for instance: "mailinator.com")

- **accepts "user@example.com"**
- **error code is DISPOSABLE_DOMAIN**
- **rejects "somebody@mailinator.com" (domain is on the disposable list)**

##### Story: MX record (for instance: fails on "no-mx.com" domain)

- **accepts "user@anything-else.com"**
- **error code is NO_MX_RECORD**
- **rejects "somebody@no-mx.com"**

##### Story: RFC format

- **accepts "user@example.com"**
- **error code is RFC_FORMAT_INVALID**
- **rejects "user test@example.com"**
- **rejects "user(comment)@example.com"**
- **rejects "user,extra@example.com"**

#### Feature: Domain

##### Story: DomainPart

- **Invariant: accepts valid values**
  - *Parameters:*
    - simple: `gmail.com`
    - Polish TLD: `home.pl`
    - subdomain: `mail.google.com`
    - compound TLD: `booking.co.uk`
- **Invariant: rejects invalid input**
  - *Parameters:*
    - no dot: `localhost`
- **normalizesToLowercaseByDefault**
  - *Parameters:*
    - normalizes: `GMAIL.COM -> gmail.com`
    - normalizes: `Gmail.Com -> gmail.com`
    - normalizes: `googlemail.com -> googlemail.com`
    - normalizes: `HOME.PL -> home.pl`
    - normalizes: `Booking.Co.Uk -> booking.co.uk`

##### Story: Email

- **Invariant: accepts valid addresses**
  - *Parameters:*
    - simple: `user@gmail.com`
    - with alias: `j.doe+spam@gmail.com`
    - Polish TLD: `user@home.pl`
    - compound TLD: `user@booking.co.uk`
- **Invariant: rejects invalid input**
  - *Parameters:*
    - single space: ` `
    - missing @: `usergmail.com`
    - multiple @: `user@@gmail.com`
    - empty local: `@gmail.com`
    - empty domain: `user@`
    - domain without dot: `user@localhost`
- **parses "JohnDoe@GMAIL.COM" to "Email{local=JohnDoe, domain=gmail.com}"**
- **parses "user@gmail.com" to "Email{local=user, domain=gmail.com}"**

##### Story: LocalPart

- **Gmail normalization**
  - *Parameters:*
    - normalizes: `J.Doe+spam -> jdoe`
    - normalizes: `j.d.o.e -> jdoe`
    - normalizes: `JDOE+work -> jdoe`
- **Invariant: accepts valid values**
  - *Parameters:*
    - plain: `user`
    - with dot: `j.doe`
    - with alias: `j.doe+spam`
    - alphanumeric: `user123`
- **Invariant: rejects invalid input**
  - *Parameters:*
    - leading dot: `.john`
    - trailing dot: `john.`
- **Outlook normalization**
  - *Parameters:*
    - normalizes: `J.Doe+alias -> j.doe`
    - normalizes: `J.Doe -> j.doe`
- **Yahoo normalization**
  - *Parameters:*
    - normalizes: `J.Doe-lists -> j.doe`
    - normalizes: `USER -> user`
- **iCloud normalization**
  - *Parameters:*
    - normalizes: `J.Doe -> j.doe`
    - normalizes: `USER -> user`

#### Feature: Use case

##### Story: CanRegister

- **Rejects with DISPOSABLE_DOMAIN when "_DisposableEmailConstraint" is unsatisfied**
- **Rejects with DOMAIN_BLOCKED when "_BlockedDomainConstraint" is unsatisfied**
- **Rejects with NOT_A_COMPANY_DOMAIN when "_IsEmployeeConstraint" is unsatisfied**
- **Rejects with RFC_FORMAT_INVALID when "_RfcFormatConstraint" is unsatisfied**
- **all constraints satisfied → allowed**
- **all error constraints satisfied, MX absent → allowed with "NO_MX_RECORD" warning**
- **if any subset of OTHER_CONSTRAINTS is unsatisfied → reject with all their codes**
  - *Parameters:*
    - OTHER_CONSTRAINTS: `[_RfcFormatConstraint, _BlockedDomainConstraint, _DisposableEmailConstraint, _IsEmployeeConstraint]`
    - broken constraints: `[RFC_FORMAT_INVALID]`
    - OTHER_CONSTRAINTS: `[_RfcFormatConstraint, _BlockedDomainConstraint, _DisposableEmailConstraint, _IsEmployeeConstraint]`
    - broken constraints: `[DOMAIN_BLOCKED, NOT_A_COMPANY_DOMAIN, DISPOSABLE_DOMAIN, RFC_FORMAT_INVALID]`
    - OTHER_CONSTRAINTS: `[_RfcFormatConstraint, _BlockedDomainConstraint, _DisposableEmailConstraint, _IsEmployeeConstraint]`
    - broken constraints: `[NOT_A_COMPANY_DOMAIN, RFC_FORMAT_INVALID]`
    - OTHER_CONSTRAINTS: `[_RfcFormatConstraint, _BlockedDomainConstraint, _DisposableEmailConstraint, _IsEmployeeConstraint]`
    - broken constraints: `[NOT_A_COMPANY_DOMAIN, RFC_FORMAT_INVALID, DOMAIN_BLOCKED, DISPOSABLE_DOMAIN]`
    - OTHER_CONSTRAINTS: `[_RfcFormatConstraint, _BlockedDomainConstraint, _DisposableEmailConstraint, _IsEmployeeConstraint]`
    - broken constraints: `[RFC_FORMAT_INVALID]`
    - OTHER_CONSTRAINTS: `[_RfcFormatConstraint, _BlockedDomainConstraint, _DisposableEmailConstraint, _IsEmployeeConstraint]`
    - broken constraints: `[NOT_A_COMPANY_DOMAIN]`
    - OTHER_CONSTRAINTS: `[_RfcFormatConstraint, _BlockedDomainConstraint, _DisposableEmailConstraint, _IsEmployeeConstraint]`
    - broken constraints: `[NOT_A_COMPANY_DOMAIN]`
    - OTHER_CONSTRAINTS: `[_RfcFormatConstraint, _BlockedDomainConstraint, _DisposableEmailConstraint, _IsEmployeeConstraint]`
    - broken constraints: `[NOT_A_COMPANY_DOMAIN, RFC_FORMAT_INVALID, DOMAIN_BLOCKED]`
    - OTHER_CONSTRAINTS: `[_RfcFormatConstraint, _BlockedDomainConstraint, _DisposableEmailConstraint, _IsEmployeeConstraint]`
    - broken constraints: `[RFC_FORMAT_INVALID, DISPOSABLE_DOMAIN, NOT_A_COMPANY_DOMAIN]`
    - OTHER_CONSTRAINTS: `[_RfcFormatConstraint, _BlockedDomainConstraint, _DisposableEmailConstraint, _IsEmployeeConstraint]`
    - broken constraints: `[RFC_FORMAT_INVALID]`

##### Story: CanResetPassword

- **Rejects with DOMAIN_BLOCKED when "_BlockedDomainConstraint" is unsatisfied**
- **Rejects with RFC_FORMAT_INVALID when "_RfcFormatConstraint" is unsatisfied**
- **all constraints satisfied → allowed**
- **if any subset of CONSTRAINTS is unsatisfied → reject with all their codes**
  - *Parameters:*
    - CONSTRAINTS: `[_RfcFormatConstraint, _BlockedDomainConstraint]`
    - broken constraints: `[RFC_FORMAT_INVALID]`
    - CONSTRAINTS: `[_RfcFormatConstraint, _BlockedDomainConstraint]`
    - broken constraints: `[DOMAIN_BLOCKED]`
    - CONSTRAINTS: `[_RfcFormatConstraint, _BlockedDomainConstraint]`
    - broken constraints: `[RFC_FORMAT_INVALID, DOMAIN_BLOCKED]`

### Epic: Hash Algorithm: Argon2

#### Feature: Configuration

- **Builder without values produces defaults**
  - *Parameters:*
    - default: `Argon2Config[iterations=Iterations[value=3], memLimit=MemLimitInKB[value=65536], parallelism=Parallelism[value=1]]`
- **Invariant: accepts valid values**
  - *Parameters:*
    - MIN: `1`
    - MAX: `16`
- **Invariant: accepts valid values**
  - *Parameters:*
    - MIN: `1`
- **Invariant: accepts valid values**
  - *Parameters:*
    - MIN: `8`
    - MAX: `4194304`
- **Invariant: rejects invalid values**
  - *Parameters:*
    - MIN - 1: `0`
    - MAX + 1: `17`
- **Invariant: rejects invalid values**
  - *Parameters:*
    - MIN - 1: `7`
    - MAX + 1: `4194305`
- **Invariant: rejects invalid values**
  - *Parameters:*
    - MIN - 1: `0`

#### Feature: Contract

##### Story: password verification

- **correct password verifies**
  - *Parameters:*
    - algorithm: `Argon2HashAlgorithm`
    - entered password: `StrongPassword1!`
    - correct password: `StrongPassword1!`
- **wrong password does not verify**
  - *Parameters:*
    - algorithm: `Argon2HashAlgorithm`
    - entered password: `StrongPassword1!23`
    - correct password: `StrongPassword1!`

### Epic: Image

#### Feature: Optimisation

- **scales an over-sized image down so its longest side fits the limit**
- **turns a BMP into a PNG, unchanged when within the limit**

### Epic: Other

#### Feature: Commenting on a meme

##### Story: comment on an existing meme

- **comment on an existing meme**

#### Feature: General

- **advance_accumulates()**
- **advance_accumulates()**
- **advance_is_thread_safe()**
- **advance_is_thread_safe()**
- **advance_moves_the_instant_forward()**
- **advance_moves_the_instant_forward()**
- **advance_moves_time_forward()**
- **advance_moves_time_forward()**
- **advance_with_a_negative_duration_moves_back()**
- **advance_with_a_negative_duration_moves_back()**
- **is_frozen_and_does_not_tick_on_its_own()**
- **is_frozen_and_does_not_tick_on_its_own()**
- **production_environment_provides_the_system_clock_and_no_controls()**
- **production_environment_provides_the_system_clock_and_no_controls()**
- **reset_returns_to_real_time()**
- **reset_returns_to_real_time()**
- **reset_returns_to_real_time()**
- **reset_returns_to_real_time()**
- **set_freezes_at_a_given_instant()**
- **set_freezes_at_a_given_instant()**
- **set_freezes_at_the_given_instant()**
- **set_freezes_at_the_given_instant()**
- **test_environment_provides_the_steerable_clock_and_the_controls()**
- **test_environment_provides_the_steerable_clock_and_the_controls()**
- **the_endpoint_steers_the_clock_the_service_injects()**
- **the_endpoint_steers_the_clock_the_service_injects()**
- **uploads_and_serves_an_optimized_meme()**
- **with_zone_shares_the_live_instant()**
- **with_zone_shares_the_live_instant()**

#### Feature: Uploading a meme

##### Story: fetch a meme's thumbnail

- **fetch a meme's thumbnail**

##### Story: upload and fetch a meme

- **upload and fetch a meme**

#### Feature: Voting on memes

##### Story: the more up-voted meme ranks higher

- **the more up-voted meme ranks higher**

### Epic: Password

#### Feature: Constraints

##### Story: Digit

- **accepts passwords with a digit**
- **error code is DIGIT_REQUIRED**
- **rejects passwords with no digit**

##### Story: Lowercase

- **accepts passwords with a lowercase letter**
- **error code is LOWERCASE_REQUIRED**
- **rejects passwords with no lowercase letter**

##### Story: Minimum length (for instance: 8 characters long)

- **accepts passwords of at least the minimum length**
- **error code is MIN_LENGTH_NOT_MET**
- **rejects passwords shorter than the minimum**

##### Story: Special char (for instance: "!")

- **accepts passwords with a special character**
- **error code is SPECIAL_CHAR_REQUIRED**
- **rejects passwords with no special character**

##### Story: Uppercase

- **accepts passwords with an uppercase letter**
- **error code is UPPERCASE_REQUIRED**
- **rejects passwords with no uppercase letter**

#### Feature: Domain

##### Story: PlaintextPassword

- **Security: toString() does not reveal plaintext**
  - *Parameters:*
    - password: `LYVa`
    - toString(): `PlaintextPassword[value=REDACTED]`
    - password: `kKRziYMJRuiHOzDwWznKqDCybsyFWJxPijWNWjsCEpQLBmJoXuhecFDMPTNnBcbEvXardUunrKOeEGMfKUTWiwVVBvJnrNTjtjvfWwexPRFkRCPVZGsaiYtYhscRXdOOnxGAtHTUwZdNkdvdnTshTlwsCgNdpOmzIZLMNeouHYmhGhbvzpuaGNmjAeUpI`
    - toString(): `PlaintextPassword[value=REDACTED]`
    - password: `rWcZqXoj`
    - toString(): `PlaintextPassword[value=REDACTED]`

#### Feature: Password Security Configuration

##### Story: MinLength

- **accepts**
  - *Parameters:*
    - MIN: `5`
- **rejects**
  - *Parameters:*
    - MIN - 1: `4`

##### Story: RequiresDigit

- **default is true**

##### Story: RequiresLowercase

- **default is true**

##### Story: RequiresUppercase

- **default is true**

##### Story: SpecialChars

- **Default value**
  - *Parameters:*
    - default: `!@#$%^&*`
- **Invariant: accepts valid values**
  - *Parameters:*
    - value: `~{!}&;@`
    - value: `!@#$%^&*`
    - value: `_\|!.%:`
    - value: `_@&~`
    - value: `!`
    - value: `!`
    - value: `!@#$%^&*`
    - value: `!@#$%^&*`
    - value: `~`
    - value: `!@#$%^&*`
- **Invariant: rejects duplicate characters**
  - *Parameters:*
    - value: `!!`
    - value: `%%`
    - value: `&&`
    - value: `~~`
    - value: `,,`
    - value: `>>`
    - value: `??`
    - value: `^^`
    - value: `\\`
    - value: `::`
    - value: `<<`
    - value: `!!`
    - value: `!!`
    - value: `;;`
    - value: `((`
    - value: `<<`
    - value: `..`
    - value: `__`
    - value: `\\`
    - value: `}}`
- **Invariant: rejects invalid values**
  - *Parameters:*
    - letter — not a special char: `a`
    - digit — not a special char: `1`

#### Feature: Password policy

##### Story: Config

- **custom policy retains PROVIDED CONFIGURATION**
  - *Parameters:*
    - minLength: `8`
    - specialChars: `$%`
    - requiresUppercase: `false`
    - requiresLowercase: `true`
    - requiresDigit: `false`
    - PROVIDED CONFIGURATION: `PasswordPolicy[minLength=MinLength[value=8], specialChars=SpecialChars[value=$%], requiresUppercase=RequiresUppercase[value=false], requiresLowercase=RequiresLowercase[value=true], requiresDigit=RequiresDigit[value=false]]`
- **withDefaults() produces DEFAULT CONFIGURATION**
  - *Parameters:*
    - DEFAULT CONFIGURATION: `PasswordPolicy[minLength=MinLength[value=5], specialChars=SpecialChars[value=!@#$%^&*], requiresUppercase=RequiresUppercase[value=true], requiresLowercase=RequiresLowercase[value=true], requiresDigit=RequiresDigit[value=true]]`

#### Feature: Use case

##### Story: Create Password Hash

- **all constraints satisfied → allowed**
- **if any subset of constraints is unsatisfied → rejected with all their codes**
  - *Parameters:*
    - broken constraints: `[SPECIAL_CHAR_REQUIRED, MIN_LENGTH_NOT_MET, UPPERCASE_REQUIRED]`
    - broken constraints: `[DIGIT_REQUIRED]`
    - broken constraints: `[SPECIAL_CHAR_REQUIRED]`
    - broken constraints: `[UPPERCASE_REQUIRED, LOWERCASE_REQUIRED, MIN_LENGTH_NOT_MET]`
    - broken constraints: `[MIN_LENGTH_NOT_MET]`
    - broken constraints: `[UPPERCASE_REQUIRED, SPECIAL_CHAR_REQUIRED]`
    - broken constraints: `[MIN_LENGTH_NOT_MET]`
    - broken constraints: `[DIGIT_REQUIRED, MIN_LENGTH_NOT_MET, UPPERCASE_REQUIRED, LOWERCASE_REQUIRED, SPECIAL_CHAR_REQUIRED]`
    - broken constraints: `[MIN_LENGTH_NOT_MET, DIGIT_REQUIRED, SPECIAL_CHAR_REQUIRED, UPPERCASE_REQUIRED, LOWERCASE_REQUIRED]`
    - broken constraints: `[MIN_LENGTH_NOT_MET]`

### Epic: Security

#### Feature: Security Configuration - AccessTokenValidityHours

##### Story: Access Token Validity [hours] config

- **accepts**
  - *Parameters:*
    - MIN: `1`
    - above MIN: `24`
- **rejects**
  - *Parameters:*
    - MIN - 1: `0`
    - negative: `-1`

#### Feature: Security Configuration - BruteForceConfig

- **Default**
  - *Parameters:*
    - default config: `BruteForceConfig[failureWindowMinutes=FailureWindowMinutes[value=15], maxFailures=MaxFailures[value=3], minBlockMinutes=MinBlockMinutes[value=3], maxBlockMinutes=MaxBlockMinutes[value=10]]`

##### Story: Failure Window Minutes Configuration

- **accepts**
  - *Parameters:*
    - MIN: `3`
    - between: `59`
    - MAX: `120`
- **rejects**
  - *Parameters:*
    - Min int: `-2147483648`
    - MIN - 1: `2`
    - MAX + 1: `121`
    - Max int: `2147483647`

##### Story: Max Block Minutes Configuration

- **accepts**
  - *Parameters:*
    - MIN: `1`
    - between: `1068`
    - MAX: `1440`
- **rejects**
  - *Parameters:*
    - Min int: `-2147483648`
    - MIN - 1: `0`
    - MAX + 1: `1441`
    - Max int: `2147483647`

##### Story: Max Failures Configuration

- **accepts**
  - *Parameters:*
    - MIN: `1`
    - between: `12`
    - MAX: `20`
- **rejects**
  - *Parameters:*
    - Min int: `-2147483648`
    - MIN - 1: `0`
    - MAX + 1: `21`
    - Max int: `2147483647`

##### Story: Min Block Minutes Configuration

- **accepts**
  - *Parameters:*
    - MIN: `1`
    - between: `15`
    - MAX: `60`
- **rejects**
  - *Parameters:*
    - Min int: `-2147483648`
    - MIN - 1: `0`
    - MAX + 1: `61`
    - Max int: `2147483647`

#### Feature: Security Configuration - RefreshTokenValidityHours

##### Story: Refresh Token Validity [hours] config

- **accepts**
  - *Parameters:*
    - MIN: `1`
    - above MIN: `168`
- **rejects**
  - *Parameters:*
    - MIN - 1: `0`
    - negative: `-1`

### Epic: Use case

#### Feature: Add comment

- **adds a comment to an existing meme**
- **refuses to comment on a missing meme**

#### Feature: Authentication

- **Authenticated when the guard allows and credentials are valid**
- **Blocked when the brute-force guard blocks the IP**
- **Rejected when the guard allows but credentials are invalid**

##### Story: Brute-force guard

- **Allowed when there is no active block and failures are below the limit**
- **Blocked and a new block created when the failure limit is reached**
- **Blocked when an active block already exists for the IP**

##### Story: Clean brute-force records

- **Removes both failed-authentication records and authentication blocks for the IP**

##### Story: Generate session

- **Creates session tokens for the email and returns the persisted result**

##### Story: Update brute-force records

- **Records a failed authentication for the IP stamped with the current time**

##### Story: Verify credentials

- **Invalid when no user exists for the email**
- **Invalid when the user exists but the password hash does not match**
- **Valid when the user exists and the password hash matches**

#### Feature: Authorize

- **Authorized when the access token maps to an unexpired session**
- **Unauthorized when no session matches the access token**
- **Unauthorized when the access token has expired**

#### Feature: Cast vote

- **an up-vote raises an existing meme's score**
- **refuses to vote on a missing meme**

#### Feature: Change email

- **A free new address starts the change and e-mails a link**
- **A matching token moves the user to the new address**
- **A taken new address is refused, nothing e-mailed**
- **An unknown token is rejected and no email is changed**

#### Feature: Change password

- **A weak new password is rejected and nothing changes**
- **A wrong current password is rejected and nothing changes**
- **Correct current password and a strong new one change the password**

#### Feature: Delete account

- **Closing the account revokes the sessions and deletes the user**

#### Feature: List active sessions

- **Returns the user's active sessions from the repository**

#### Feature: Logout

- **Logging out an unknown session is a no-op**
- **Logging out revokes the whole family of the session named by the refresh token**

#### Feature: Make thumbnail

- **makes a small PNG thumbnail of a stored meme**
- **no thumbnail for a missing meme**

#### Feature: Publish meme

- **publishes an optimized meme**
- **publishing the same image twice reuses the meme (dedup)**

#### Feature: Rank memes

- **ranks memes by score, highest first**

#### Feature: Refresh session

- **Expired: an active but expired token is rejected, nothing is rotated**
- **NotFound: no session matches the refresh token**
- **Refreshed: an active, unexpired token rotates to a new one in the same family**
- **ReuseDetected: replaying a rotated token revokes the whole family**

#### Feature: Register

- **EmailAlreadyTaken when a user with that email already exists**
- **Registered when both email and password pass validation**
- **Rejected when email, password, or both fail validation**

#### Feature: Reset password

- **A valid token and strong password reset the password**
- **A weak new password is rejected without consuming the token**
- **An unknown token is rejected and no password is changed**

#### Feature: Revoke all sessions

- **Revoking all sessions revokes every session of the user**

#### Feature: Verify email

- **A matching token verifies the address**
- **An unknown token is rejected**

