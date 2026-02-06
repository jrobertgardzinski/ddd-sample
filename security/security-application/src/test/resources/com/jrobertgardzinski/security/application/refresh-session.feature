Feature: refresh session

    Background:
    Given a user with email "user@gmail.com"

    Rule: 1. A valid refresh token grants new session tokens

        Example:
        Given the user has an active session
        When the user refreshes the session
        Then the user receives new session tokens

    Rule: 2. An expired refresh token is rejected

        Example:
        Given the user has an expired session
        When the user refreshes the session
        Then the refresh fails due to RefreshTokenExpiredEvent

    Rule: 3. A non-existent refresh token is rejected

        Example:
        Given the user has no session
        When the user refreshes the session
        Then the refresh fails due to NoRefreshTokenFoundEvent
