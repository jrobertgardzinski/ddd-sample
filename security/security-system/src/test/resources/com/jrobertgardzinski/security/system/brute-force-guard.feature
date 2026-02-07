Feature: brute force guard

    Background:
    Given the system receives an authentication request from IP "192.168.1.1"

    Rule: 1. Guard lets the authentication through when ...

        Scenario Outline: ... the failure count is below the limit
        Given no blockade is set for the IP
        And failures count for the IP equals to <failures_count>
        When the brute force guard checks the IP
        Then the guard lets the authentication through

        Examples:
            | failures_count |
            | 0              |
            | 1              |
            | 2              |

    Rule: 2. Guard blocks authentication when the failure count reaches the limit

        Scenario: Failure limit reached
        Given no blockade is set for the IP
        And failures count for the IP equals to 3
        When the brute force guard checks the IP
        Then the guard blocks the authentication

    Rule: 3. Guard blocks authentication when an active blockade exists for the IP

        Scenario: Active blockade
        Given an active blockade exists for the IP
        When the brute force guard checks the IP
        Then the guard blocks the authentication

    Rule: 4. Guard only counts failures from the last 15 minutes

        Scenario Outline:
        Given no blockade is set for the IP
        And 3 failures recorded <minutes_ago> minutes ago for the IP
        When the brute force guard checks the IP
        Then the guard <result>

        Examples:
            | minutes_ago | result                            |
            | 15          | lets the authentication through   |
            | 14          | blocks the authentication         |
