Feature: verify credentials

    Background:
    Given a user with an email "user@gmail.com"
    And a password "StrongPassword1!" is registered

	Rule: 1. A user has to provide valid credentials for authentication

		Scenario: Positive
		When the user passes the "user@gmail.com" email
		And the "StrongPassword1!" password
		Then the authentication passes

    Rule: 2. Handling invalid credentials

		Scenario Outline: Wrong credentials
		When the user passes the "<email>" email
		And the "<password>" password
		Then authentication fails due to <error>

		Examples:
		| email                  | password                 | error                     |
		| another-user@gmail.com | WrongButStrongPassword1! | AuthenticationFailedEvent  |
		| another-user@gmail.com | StrongPassword1!         | AuthenticationFailedEvent  |
		| user@gmail.com         | WrongButStrongPassword1! | AuthenticationFailedEvent  |
