@http-only
Feature: Federated sign-in

  A USER SIGNS IN with an identity an external PROVIDER vouches for. Registration
  collapses into the first sign-in, and one ACCOUNT may hold many identities —
  a password and a provider subject are equal keys to the same ACCOUNT.

  Rule: 1. A vouched identity SIGNS the USER IN, creating the ACCOUNT at first contact

    Example: first contact
      When the USER SIGNS IN with a PROVIDER identity vouching for "newcomer@example.com"
      Then the USER is SIGNED IN
      And the ACCOUNT "newcomer@example.com" exists, verified from birth

    Example: the second contact opens the same ACCOUNT, not a twin
      Given the USER already SIGNED IN with a PROVIDER identity vouching for "regular@example.com"
      When the USER SIGNS IN with a PROVIDER identity vouching for "regular@example.com"
      Then the USER is SIGNED IN
      And the ACCOUNT "regular@example.com" is the one that already existed

  Rule: 2. A verified local ACCOUNT auto-links: the same inbox proved twice is the same person

    Example: forgot the password sign-up, came back through the provider
      Given a local ACCOUNT "veteran@example.com" with a verified email and the password "StrongPassword1!"
      When the USER SIGNS IN with a PROVIDER identity vouching for "veteran@example.com"
      Then the USER is SIGNED IN
      And the password "StrongPassword1!" still opens the ACCOUNT "veteran@example.com"

  Rule: 3. An unverified local ACCOUNT is taken over: the PROVIDER's proof beats an unproven password

    Example: a squatter planted an account on someone else's address
      Given a local ACCOUNT "victim@example.com" with an unverified email and the password "SquatterPass1!"
      And the ACCOUNT "victim@example.com" holds an active session
      When the USER SIGNS IN with a PROVIDER identity vouching for "victim@example.com"
      Then the USER is SIGNED IN
      And the password "SquatterPass1!" no longer opens the ACCOUNT "victim@example.com"
      And every previous session of "victim@example.com" is revoked

  Rule: 3b. A provider login is only link #1 — enrolled factors must still be passed

    Example: a federated account that turned on a second factor
      Given a local ACCOUNT "guarded@example.com" with a verified email and the password "StrongPassword1!"
      And the ACCOUNT "guarded@example.com" has enrolled an e-mail FACTOR
      When the USER SIGNS IN with a PROVIDER identity vouching for "guarded@example.com"
      Then the SIGN IN needs a further FACTOR

  Rule: 3c. An ACCOUNT locked by a running deletion is refused WITHOUT being touched

    Example: the leaver clicks "sign in with the provider" while their deletion is running
      Given a local ACCOUNT "leaver@example.com" with an unverified email and the password "SquatterPass1!"
      And a DELETION is running for "leaver@example.com"
      When the USER SIGNS IN with a PROVIDER identity vouching for "leaver@example.com"
      Then the SIGN IN is refused
      And the password "SquatterPass1!" still opens the ACCOUNT "leaver@example.com"
      And the ACCOUNT "leaver@example.com" is still unverified
      And no PROVIDER identity is linked to "leaver@example.com"

  Rule: 4. An identity the PROVIDER does not vouch for touches nothing

    Example: the provider did not verify the email
      When the USER SIGNS IN with a PROVIDER identity NOT vouching for "shady@example.com"
      Then the SIGN IN is refused
      And no ACCOUNT "shady@example.com" exists
