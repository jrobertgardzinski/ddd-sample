Feature: authenticate

    Background:
    Given a registered user with email "user@gmail.com" and password "StrongPassword1!"
    And the authentication attempt comes from IP "192.168.1.1"

    Rule: 1. Successful authentication returns session tokens

        Scenario: Valid credentials and no brute force block
        Given the IP has no blockade
        And the IP has 0 recorded failures
        When the user authenticates with email "user@gmail.com" and password "StrongPassword1!"
        Then the authentication result is passed

    Rule: 2. Authentication fails when credentials are wrong

        Scenario Outline: Wrong credentials
        Given the IP has no blockade
        And the IP has 0 recorded failures
        When the user authenticates with email "<email>" and password "<password>"
        Then the authentication result is failed

        Examples:
        | email                  | password                 |
        | another-user@gmail.com | WrongButStrongPassword1! |
        | another-user@gmail.com | StrongPassword1!         |
        | user@gmail.com         | WrongButStrongPassword1! |

    Rule: 3. Authentication is blocked when brute force protection is active

        Scenario: Active blockade exists for the IP
        Given the IP has an active blockade
        When the user authenticates with email "user@gmail.com" and password "StrongPassword1!"
        Then the authentication result is blocked

        Scenario: Failure limit reached
        Given the IP has no blockade
        And the IP has 3 recorded failures
        When the user authenticates with email "user@gmail.com" and password "StrongPassword1!"
        Then the authentication result is blocked
