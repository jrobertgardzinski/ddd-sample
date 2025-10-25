Feature: register

  Anyone can register a new user just by passing an email and password.

  Rule: Email and password are validated

    Scenario Outline: Passing wrong email and password
      When I pass an email <email>
      And I pass a password <password>
      Then I get an error <error>

      Examples:
        | email                 | password         | error    |
        | user_AT_gmail_DOT_com | secret           | both     |
        | user_AT_gmail_DOT_com | StrongPassword1! | password |
        | user@gmail.com        | StrongPassword1! | email    |

    Scenario: : Passing validation
      When I pass an email "user@gmail.com"
      And I pass a password "StrongPassword1!"
      Then the request passes