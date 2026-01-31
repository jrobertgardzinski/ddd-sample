# todo must be more descriptive. "I get validation error for email" tells nothing. Should be more explicit.
Feature: register input validation

    Rule: 1. Email must be valid

        Scenario: Invalid email format
        When I create user registration with email "invalid_email" and password "StrongPassword1#"
        Then I get validation error for email

    Rule: 2. Password must satisfy strong password policy

        Scenario: Password too weak
        When I create user registration with email "user@gmail.com" and password "weak"
        Then I get validation error for password

        Scenario: Password violates multiple rules
        When I create user registration with email "user@gmail.com" and password "weak"
        Then I get validation errors for password:
            | must be at least 12 characters long           |
            | must contain an uppercase letter              |
            | must contain a digit                          |
            | must contain one of special characters: [#?!] |

    Rule: 3. Both email and password are validated together

        Scenario: Both invalid
        When I create user registration with email "invalid" and password "x"
        Then I get validation error for email
        And I get validation error for password
