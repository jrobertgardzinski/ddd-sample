Feature: generate session

    Background:
    Given an authenticated user with email "user@gmail.com"

    Rule: 1. Session tokens are generated after successful authentication

        Scenario: Generate session tokens
        When the system generates a session
        Then the session contains a refresh token
        And the session contains an access token
