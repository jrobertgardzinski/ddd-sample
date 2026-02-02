Feature: register

    Rule: 0. Input is validated

        Example:
        When I register with invalid arguments
        Then registration fails on validating input arguments

    Rule: 1. Anyone can register a new user just by passing an email and password.

        Example:
        When I register with an email "user@gmail.com" and a password "StrongPassword1#"
        Then registration passes

    Rule: 2. Registering a new user with already registered email causes failure

        Example:
        Given a user with an email "user@gmail.com" has already been registered
        When I register with an email "user@gmail.com" and any other required valid parameters
        Then registration fails