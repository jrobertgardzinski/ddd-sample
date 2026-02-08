Feature: register

    Rule: 1. The system registers a new account given an email and password

        Example:
        When the system receives a registration with email "user@gmail.com" and password "StrongPassword1#"
        Then the registration passes

    Rule: 2. The system rejects registration when the email is already taken

        Example:
        Given the system already has an account with email "user@gmail.com"
        When the system receives a registration with email "user@gmail.com" and password "StrongPassword1#"
        Then the registration fails
