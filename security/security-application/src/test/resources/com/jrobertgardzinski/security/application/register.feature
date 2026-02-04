Feature: register

    Rule: 0. Input is validated

        Scenario Outline: <case>
        When I register with an email "<email>" and a password "<password>"
        Then registration fails on validating input arguments
        And there are <email_errors> email errors
        And there are <password_errors> password errors

        Examples:
            | case                       | email          | password         | email_errors | password_errors |
            | invalid email and password | invalid        | weak             | some         | some            |
            | invalid email only         | invalid        | StrongPassword1# | some         | no              |
            | invalid password only      | user@gmail.com | weak             | no           | some            |

    Rule: 1. Anyone can register a new user just by passing an email and password.

        Example:
        When I register with an email "user@gmail.com" and a password "StrongPassword1#"
        Then registration passes

    Rule: 2. Registering a new user with already registered email causes failure

        Example:
        Given a user with an email "user@gmail.com" has already been registered
        When I register with an email "user@gmail.com" and any other required valid parameters
        Then registration fails