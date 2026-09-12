@ui
Feature: Changing the email address

  A signed-in USER changes their EMAIL by proving ownership of the new one: a verification link goes
  to the new EMAIL, and confirming the token applies the change. Afterwards they AUTHENTICATE under
  the new EMAIL and no longer under the old one. An unknown token is rejected.

  Background:
    Given a registered USER "user@example.com" with password "StrongPassword1!"

  Rule: Confirming the token from the link CHANGES the EMAIL

    Example:
      Given the USER has AUTHENTICATED
      When the USER requests to CHANGE the EMAIL to "new@example.com"
      And the USER CONFIRMS the EMAIL CHANGE with the token from the link
      Then the USER can AUTHENTICATE as "new@example.com"
      And the USER cannot AUTHENTICATE as "user@example.com"

  Rule: An unknown token is rejected

    Example:
      When the USER CONFIRMS the EMAIL CHANGE with a garbage token
      Then the EMAIL CHANGE is rejected

  Rule: A taken EMAIL cannot be probed through the change — the reply is quiet, the owner is told by mail

    Example:
      Given another ACCOUNT already holds "occupied@example.com"
      And the USER has AUTHENTICATED
      When the USER requests to CHANGE the EMAIL to "occupied@example.com"
      Then the CHANGE request is quietly refused, indistinguishable from a fresh one
      And the owner of "occupied@example.com" is notified by mail

  Rule: FEDERATED LINKS follow the account — the subject is the person, not the address

    The link is keyed by the provider's durable subject: the same Google account belongs to the
    same person after the change. Severing it instead would orphan the identity (the provider
    keeps reporting its own old address, so the auto-link would never find the moved account —
    and could even find a stranger who registered the freed one).

    # federated linking has no UI surface in this harness (the OAuth dance needs the stub IdP);
    # the JVM glue drives this example over the wire
    @http-only
    Example:
      Given the USER also signs in through "google" as subject "subject-7"
      And the USER has AUTHENTICATED
      When the USER requests to CHANGE the EMAIL to "fresh@example.com"
      And the USER CONFIRMS the EMAIL CHANGE with the token from the link
      Then the "google" identity "subject-7" opens the account "fresh@example.com"

  Rule: SESSIONS do not follow the account — after a CHANGE the USER signs in again

    A session remembers the address it was minted for and nothing else, so it cannot be moved.
    One left alive keeps authorizing as the OLD address: "sign out everywhere" under the new
    address never reaches it, and the moment somebody REGISTERS the freed address it starts
    answering for THEIR account. So the CHANGE revokes them, the same price a password CHANGE
    already charges.

    # the browser signs in again on its own after the change, so the stale-token assertion is
    # wire-level; the JVM glue drives this example
    @http-only
    Example:
      Given the USER has AUTHENTICATED
      When the USER requests to CHANGE the EMAIL to "moved@example.com"
      And the USER CONFIRMS the EMAIL CHANGE with the token from the link
      Then the SESSION held since before the CHANGE no longer authorizes
