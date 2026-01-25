Feature: register

    Rule: 1. Anyone can register a new user just by passing an email and password.

        Scenario: Positive
        When I pass an email "user@gmail.com" and a password "StrongPassword1!"
        And I try to register
        Then registration passes

    Rule: 2. Registering a new user with already registered email causes failure

        Scenario: Sample
        Given a user with an email "user@gmail.com" has already been registered
        When I pass an email "user@gmail.com" and a password "StrongPassword1!"
        And I try to register
        Then registration fails

    Rule: 3. Email and password are validated

        Scenario Outline: Passing wrong email and password
        When I pass an email "<email>" and a password "<password>"
        And I try to register
        Then I get an error for <validation_failed_for>

        Examples:
            | email                 | password         | validation_failed_for |
            | user_AT_gmail_DOT_com | secret           | ALL                   |
            | user_AT_gmail_DOT_com | StrongPassword1! | email                 |
            | user@gmail.com        | secret           | password              |