# @http-only, not @ui: the policy is an ADMIN's lever and an operator's report — no browser
# page reads it yet, so the wire glue owns it.
@http-only
Feature: Setting the minimum password length while the system runs

  How long a password must be is a decision, not a constant. The programmer
  ships a default, the operator may override it for one deployment, and an ADMIN
  may override both while the system runs — from that moment every place a
  password is established measures against the new floor. The floor has a floor
  of its own: a length the policy considers meaningless is refused at the door
  and nothing changes. And because the value in force comes from a ladder of
  sources, an ADMIN can always ask which source answered and what was refused on
  the way — the only way to learn that a row someone wrote straight into the
  database is not the value the system lives by.

  # The ladder for this key: a security_settings row (live) over the
  # security.password.policy.min.length property (restart) over MinLength.DEFAULT (rebuild).
  # The test deployment sets no property, so a vacant live level falls to the default of 5.
  # The live level is one snapshot of the whole table, read at the start and after each ADMIN's
  # write, never on a question — so EVERY key of the policy has it, endpoint or no endpoint. The
  # table is the service's own and the API is the only way in: a row written at the console is
  # in force from the next start, and the ladder's gate is what keeps such a hand from putting an
  # illegal value in force. The report an ADMIN asks for is the whole policy: every rule under
  # its key, each with the level that answered.

  Background:
    Given a registered USER "member@example.com" with password "StrongPassword1!"
    And a registered USER "admin@example.com" with password "StrongPassword1!"

  Rule: An ADMIN sets the minimum length, and from then on the running system measures against it

    Example:
      When the ADMIN SETS the minimum password length to 10
      Then the minimum password length in force is 10, decided by the "live (database)" source
      And the USER REGISTERS with EMAIL "newcomer@example.com" and password "Nine1!aaa"
      And REGISTRATION is rejected
      And the password is flagged as MIN_LENGTH_NOT_MET
      And the refusal names the minimum length in force, 10

  Rule: A length below the policy's own floor is refused and nothing changes

    Example:
      Given the ADMIN has SET the minimum password length to 10
      When the ADMIN SETS the minimum password length to 3
      Then the request is refused because "minLength must be at least 5"
      And the minimum password length in force is 10, decided by the "live (database)" source

  Rule: A value written straight into the database is not law — the ladder refuses it, falls through, and says so

    Example:
      Given the database row for the minimum password length holds 3, written at the console before the last start
      When the ADMIN asks for the password policy in force
      Then the minimum password length in force is 5, decided by the "rebuild (default)" source
      And the report says the "live (database)" source was refused holding 3 because "minLength must be at least 5"

  Rule: Every rule of the policy reads the same table, endpoint or no endpoint

    Example:
      Given the database row "security.password.policy.requires.digit" holds "false", written at the console before the last start
      When the ADMIN asks for the password policy in force
      Then the rule "security.password.policy.requires.digit" in force is "false", decided by the "live (database)" source
      And the USER REGISTERS with EMAIL "nodigit@example.com" and password "NoDigitsHere!"
      And REGISTRATION succeeds

    Example:
      Given the database row "security.password.policy.requires.digit" holds "maybe", written at the console before the last start
      When the ADMIN asks for the password policy in force
      Then the rule "security.password.policy.requires.digit" in force is "true", decided by the "rebuild (default)" source
      And the report says the rule "security.password.policy.requires.digit" was refused holding the text "maybe"

  Rule: Setting the minimum password length is an ADMIN's hand alone

    Example:
      When "member@example.com" tries to SET the minimum password length to 10
      Then the request is forbidden
