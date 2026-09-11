@ui
Feature: Closing the account

  An account is closed in one of two ways, and which one it is decides what may survive it. A
  USER closes their OWN account and everything they ever posted goes with it: they are exercising
  the right to be forgotten, and there is no rule under which a portal may keep the content of
  somebody who asked to be forgotten because it happened to be popular. An ADMIN closes SOMEBODY
  ELSE's account — a ban, house rules — and nobody is exercising any right, so the ADMIN may say
  what happens to each kind of content: delete it, keep it without its author, or keep only what
  the community voted up, again without its author.

  Either way the closure is a SAGA across services: the account locks at once (sessions revoked,
  sign-in refused) and identity announces the deletion to the PORTAL, whose own orchestrator has
  every content service purge that person's content; votes are retracted. Identity waits for the
  portal's single outcome: only "content purged" deletes the account for good; a failed purge —
  or silence past the safety net — rolls the closure back.

  Background:
    Given a registered USER "user@example.com" with password "StrongPassword1!"
    And a registered USER "admin@example.com" with password "StrongPassword1!"

  Rule: Requesting closure locks the account immediately

    Example:
      Given the USER has AUTHENTICATED
      When the USER requests account DELETION
      Then the access token no longer authorizes
      And the USER cannot AUTHENTICATE with "StrongPassword1!"
      And the email is not yet free to REGISTER

  Rule: A USER closing their own account takes all of it with them

    # the fact names WHO asked, and that is what the content services read before they honour any
    # condition at all — a self-closure states no conditions and cannot be made to state any
    @http-only
    Example:
      Given the USER has AUTHENTICATED
      When the USER requests account DELETION
      Then the announced deletion says the USER asked for it
      And the announced deletion carries no conditions

  Rule: The address in the path may be spelled differently — it is still your own account

    # the two are compared the way registration compares them, so a shouted DOMAIN never sends a
    # caller down the administrator's road; what travels on is the stored spelling
    @http-only
    Example:
      Given the USER has AUTHENTICATED
      When the USER requests account DELETION spelling their address differently
      Then the announced deletion says the USER asked for it
      And the USER cannot AUTHENTICATE with "StrongPassword1!"

  Rule: An ADMIN closing somebody else's account may keep what the community voted up

    @http-only
    Example:
      When the ADMIN CLOSES "user@example.com" keeping content with at least 100 votes
      Then the announced deletion says an ADMIN asked for it
      And the announced deletion carries that choice
      And the USER cannot AUTHENTICATE with "StrongPassword1!"

  Rule: Closing somebody else's account is an ADMIN's hand alone

    @http-only
    Example:
      When "user@example.com" tries to CLOSE "admin@example.com"
      Then the request is forbidden

  Rule: An ADMIN cannot close an account that does not exist

    @http-only
    Example:
      When the ADMIN CLOSES "nobody@example.com" keeping content with at least 100 votes
      Then the request is not found

  Rule: The closure completes only when the PORTAL confirmed its content purged

    @http-only
    Example:
      Given the USER has AUTHENTICATED
      And the USER requested account DELETION
      Then the email is not yet free to REGISTER
      When the portal confirms the content purge
      Then the USER can REGISTER again with "StrongPassword1!"

  Rule: A failed portal purge rolls the closure back

    @http-only
    Example:
      Given the USER has AUTHENTICATED
      And the USER requested account DELETION
      When the portal reports the content purge failed
      Then the USER can AUTHENTICATE again with "StrongPassword1!"

  Rule: Even total silence rolls the closure back (the safety net)

    @http-only
    Example:
      Given the USER has AUTHENTICATED
      And the USER requested account DELETION
      When no portal outcome arrives within the time limit
      Then the USER can AUTHENTICATE again with "StrongPassword1!"
