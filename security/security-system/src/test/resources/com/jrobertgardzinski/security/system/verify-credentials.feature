Feature: verify credentials

    Background:
    Given the system has a registered account with email "user@gmail.com" and password "StrongPassword1!"

	Rule: 1. The system verifies valid credentials

		Scenario: Positive
		When the system receives credentials with email "user@gmail.com" and password "StrongPassword1!"
		Then the verification passes

    Rule: 2. The system rejects invalid credentials

		Scenario Outline: Wrong credentials
		When the system receives credentials with email "<email>" and password "<password>"
		Then the verification fails due to <error>

		Examples:
		| email                  | password                 | error                     |
		| another-user@gmail.com | WrongButStrongPassword1! | AuthenticationFailedEvent  |
		| another-user@gmail.com | StrongPassword1!         | AuthenticationFailedEvent  |
		| user@gmail.com         | WrongButStrongPassword1! | AuthenticationFailedEvent  |
