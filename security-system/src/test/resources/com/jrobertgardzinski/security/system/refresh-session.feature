Feature: refresh session

    Background:
    Given the system holds a session for email "user@gmail.com"

    Rule: 1. The system grants new session tokens for a valid refresh token

        Example:
        Given the session is active
        When the system processes a session refresh request
        Then the system returns new session tokens

    Rule: 2. The system rejects an expired refresh token

        Example:
        Given the session is expired
        When the system processes a session refresh request
        Then the system rejects with RefreshTokenExpiredEvent

    Rule: 3. The system rejects a non-existent refresh token

        Example:
        Given the session does not exist
        When the system processes a session refresh request
        Then the system rejects with NoRefreshTokenFoundEvent
