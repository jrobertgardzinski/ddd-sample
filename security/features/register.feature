Feature: register

  Anyone can register a new user just by passing an email and password.

  Scenario: Positive
    When I pass an email "user@gmail.com"
    And I pass a password "StrongPassword1!"
    Then the request succeeds

  Rule: Email and password are validated

    Scenario Outline: Passing wrong email and password
      When I pass an email <email>
      And I pass a password <password>
      Then I get an error for <validation_failed_for>

      Examples:
        | email                 | password         | validation_failed_for |
        | user_AT_gmail_DOT_com | secret           | ALL                   |
        | user_AT_gmail_DOT_com | StrongPassword1! | email                 |
        | user@gmail.com        | StrongPassword1! | password              |

  Rule: Registering a new user with already registered email causes failure

    Scenario: Sample
      Given a user with an email "user@gmail.com" has already been registered
      When another user tries to use the same email for registration
      Then registration fails