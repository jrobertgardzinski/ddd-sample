Feature: authenticate

	User authentication

	Rule: 1. A user has to provide valid credentials for authentication

		Background: 
		Given a user with an email "user@gmail.com" 
		And a password "StrongPassword1!" is registered

		Scenario: Positive
		When the user passes the "user@gmail.com" email
		And the "StrongPassword1!" password
		Then the authentication passes
	
		Scenario Outline: Negative
		When the user passes the <email> email
		And the <password> password
		Then authentication fails due to <error>

		Examples:
		| email                  | password                 | error              |
		| another-user@gmail.com | WrongButStrongPassword1! | UserNotFoundEvent  |
		| another-user@gmail.com | StrongPassword1!         | UserNotFoundEvent  |
		| user@gmail.com         | WrongButStrongPassword1! | WrongPasswordEvent |
