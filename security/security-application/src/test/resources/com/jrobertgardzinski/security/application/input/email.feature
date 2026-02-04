Feature: email

    Rule: 0. Is required

        Example:
        When I provide no email
        Then email creation fails

    Rule: 1. Must match email format

        Example:
        When I create an email from "invalid"
        Then email creation fails

    Rule: 2. Valid email is accepted

        Example: The shortest e-mail possible
        When I create an email from "a@a.a"
        Then email creation passes

        Example: A typical e-mail
        When I create an email from "user@example.com"
        Then email creation passes
