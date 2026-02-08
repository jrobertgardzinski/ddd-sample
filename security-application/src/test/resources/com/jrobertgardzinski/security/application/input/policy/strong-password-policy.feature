Feature: strong password policy

    Rule: 0. Password must satisfy all requirements

        Scenario Outline: <requirement>
        When I validate "<password>" against strong password policy
        Then the policy reports "<violation>"

        Examples:
            | requirement        | password         | violation                                     |
            | minimum length     | Short1#          | must be at least 12 characters long            |
            | a lowercase letter | STRONGPASSWORD1# | must contain a lowercase letter                |
            | an uppercase letter| strongpassword1# | must contain an uppercase letter               |
            | a digit            | StrongPassword## | must contain a digit                           |
            | a special character| StrongPassword12 | must contain one of special characters: [#?!]  |

    Rule: 1. Fixing violations one by one

        Scenario Outline: <step>
        When I validate "<password>" against strong password policy
        Then the policy reports <count> violations

        Examples:
            | step                | password      | count |
            | abc violates 4      | abc           | 4     |
            | fix length          | abcabcabcabc  | 3     |
            | fix uppercase       | Abcabcabcabc  | 2     |
            | fix digit           | Abcabcabcab1  | 1     |
            | fix special char    | Abcabcabcab1# | 0     |

    Rule: 2. Valid password satisfies the policy

        Example:
        When I validate "StrongPassword1#" against strong password policy
        Then the password satisfies the policy
