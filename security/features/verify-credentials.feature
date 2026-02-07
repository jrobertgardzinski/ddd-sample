Feature: verify credentials

  User authentication

  Background:
    Given a user with email "user@gmail.com"
    And password "StrongPassword1!" is registered

  Scenario: Positive
    When the user passes email "user@gmail.com"
    And password "StrongPassword1!"
    Then the user retrieves session tokens

  Rule: Passing wrong credentials

   Scenario Outline:
     When the user passes email <email>
     And password <password>
     Then authentication fails

     Examples:
       | email                  | password                 |
       | another-user@gmail.com | WrongButStrongPassword1! |
       | another-user@gmail.com | StrongPassword1!         |
       | user@gmail.com         | WrongButStrongPassword1! |

     # 3 failures in a row etc.
