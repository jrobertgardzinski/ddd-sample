# @http-only, not @ui: the catalogue is an ADMIN's lever and an operator's report — no browser
# page reads it yet, so the wire glue owns it.
@http-only
Feature: Setting any live rule while the system runs

  A rule the programmer ships with a default and the operator may override for one
  deployment may also be overridden by an ADMIN while the system runs — when it is
  declared live. The declaration is the only way onto the list: whatever an ADMIN
  can set is something the system reads, and the value passes the rule's own gate
  on the way in, exactly as it would on the way out, so a value the rule would
  refuse is refused at the door and nothing changes. No rule needs code of its own
  to be settable — the next rule declared live is on the list the moment it is
  declared, and a key nobody declared cannot be set, because nobody reads it.

  # Every key is set by name through PUT /admin/settings/{key} with {"value": ...}. The value is
  # text, the way a property or a row holds it, parsed by the rule's type (an integer, a flag, a
  # constant) and gated by the rule's constructor — the same parser and gate the ladder reads a
  # row with. GET /admin/settings lists the catalogue: what is in force under each key and which
  # level decided it. The test deployment sets no property, so a vacant live level falls to the
  # shipped default; the keys below are the password policy's, the rules declared live today.

  Background:
    Given a registered USER "member@example.com" with password "StrongPassword1!"
    And a registered USER "admin@example.com" with password "StrongPassword1!"

  Rule: An ADMIN sets a rule by its key, and from then on the running system lives by it

    Example: a flag
      When the ADMIN SETS "security.password.policy.requires.digit" to "false"
      Then the setting is ACCEPTED holding "false"
      And "security.password.policy.requires.digit" in force is "false", decided by the "live (database)" source
      And the USER REGISTERS with EMAIL "nodigit@example.com" and password "NoDigitsHere!"
      And REGISTRATION succeeds

    Example: a number, in any spelling its type reads
      When the ADMIN SETS "security.password.policy.min.length" to " 10 "
      Then the setting is ACCEPTED holding "10"
      And "security.password.policy.min.length" in force is "10", decided by the "live (database)" source

  Rule: A value the rule refuses is refused at the door, in the rule's words, and nothing changes

    Example: below the rule's own floor
      When the ADMIN SETS "security.password.policy.min.length" to "3"
      Then the setting is REFUSED because "minLength must be at least 5"
      And "security.password.policy.min.length" in force is "5", decided by the "rebuild (default)" source

    Example: not the rule's type
      When the ADMIN SETS "security.password.policy.requires.digit" to "maybe"
      Then the setting is REFUSED because "'maybe' is not the type this key takes"
      And "security.password.policy.requires.digit" in force is "true", decided by the "rebuild (default)" source

  Rule: A key nobody declared live cannot be set, because nobody reads it

    Example: a typo in the key
      When the ADMIN SETS "security.password.policy.min.lenght" to "10"
      Then the setting is UNKNOWN
      And nothing was written under "security.password.policy.min.lenght"

  Rule: The catalogue is exactly what the system declared live, with what is in force under each key

    Example:
      When the ADMIN asks for the catalogue
      Then the catalogue lists exactly "security.password.policy.min.length", "security.password.policy.special.chars", "security.password.policy.requires.uppercase", "security.password.policy.requires.lowercase" and "security.password.policy.requires.digit"
      And every entry says what is in force and which source decided it

  Rule: Setting a rule is an ADMIN's hand alone

    Example:
      When "member@example.com" tries to SET "security.password.policy.min.length" to "10"
      Then the request is forbidden
