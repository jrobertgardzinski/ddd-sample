Feature: register

    Rule: 1. Anyone can register a new user just by passing an email and password.

        Scenario: Positive
        When I pass an email "user@gmail.com" and a password "StrongPassword1#"
        And I try to register
        Then registration passes

    Rule: 2. Registering a new user with already registered email causes failure

        Scenario: Sample
        Given a user with an email "user@gmail.com" has already been registered
        When I pass an email "user@gmail.com" and any other required valid parameters
        And I try to register
        Then registration fails