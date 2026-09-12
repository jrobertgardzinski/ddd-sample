@ui
Feature: Verifying an email address

  A USER proves they own their EMAIL by following a verification link sent to it. The link
  carries a single-use VERIFICATION TOKEN; the matching token marks the EMAIL as verified, and
  an unknown token is rejected.

  Background:
    Given a registered USER "user@example.com" with password "StrongPassword1!" whose EMAIL is not verified yet

  Rule: The VERIFICATION TOKEN from the link verifies the EMAIL

    Example:
      Given the USER requested EMAIL VERIFICATION
      When the USER VERIFIES the EMAIL with the VERIFICATION TOKEN from the link
      Then the EMAIL is verified

  Rule: An unknown VERIFICATION TOKEN is rejected

    Example:
      When the USER VERIFIES the EMAIL with a garbage VERIFICATION TOKEN
      Then the VERIFICATION is rejected

  Rule: Registration automatically starts VERIFICATION

    Example:
      Then a VERIFICATION link has been e-mailed to the USER

  Rule: Requesting VERIFICATION for an already verified EMAIL changes nothing

    Anyone may ask for a link for any address — the endpoint is public and answers the same for
    every address, so that nobody can probe who is registered here. That answer must cost the
    owner nothing: a verified EMAIL stays verified and no new link goes out. Otherwise one
    request per victim shuts them out of their own account, because signing in demands a
    verified address.

    Example:
      Given the USER has VERIFIED the EMAIL
      When EMAIL VERIFICATION is requested again for that EMAIL
      Then the request is accepted as quietly as any other
      And the EMAIL is still verified
      And no new VERIFICATION link was e-mailed
