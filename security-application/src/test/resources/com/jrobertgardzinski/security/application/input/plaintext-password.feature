Feature: plaintext password

    Rule: 0. Is required

        Example:
        When I provide no password
        Then password creation fails

    Rule: 1. Valid password

        Example:
        When I create a password from "StrongPassword1#"
        Then password creation passes
