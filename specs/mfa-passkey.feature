@ui
Feature: Passkey sign-in

  A USER may enrol a PASSKEY — a possession FACTOR, nothing to type and nothing to copy.
  Once enrolled, the password alone no longer signs in: the device holding the PASSKEY
  must prove it is present. This exercises the same factor chain the e-mail and TOTP
  factors use, proving the factor port is genuinely plug-and-play. (The protocol behind
  a passkey is an implementation detail and lives in the glue — the argon2 rule.)

  Background:
    Given a verified USER "passkey@example.com" with password "StrongPassword1!"
    And the USER has a device that can hold PASSKEYS

  Rule: An enrolled PASSKEY signs the USER in without a typed code

    Example:
      Given the USER has ENROLLED a PASSKEY
      When the USER AUTHENTICATES with the correct password
      Then the USER is signed in by the PASSKEY

  Rule: Only the device signs the USER in — an ENROLMENT answer never does

    The PASSKEY step hands out a fresh CHALLENGE for the device to sign, and that CHALLENGE is
    public: it travels to whoever passed the password step. Sending it back as if a NEW PASSKEY
    were being ENROLLED proves possession of nothing, so a stolen password stays one step short
    of a session — at sign-in and at every STEP-UP the PASSKEY guards.

    Example:
      Given the USER has ENROLLED a PASSKEY
      When the correct password is answered with an ENROLMENT instead of the PASSKEY
      Then the sign-in is refused and no session is issued
