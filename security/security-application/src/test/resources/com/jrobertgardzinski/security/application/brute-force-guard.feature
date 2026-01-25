Feature: brute force guard

	Prevent brute force attack.
	# todo Isn't it a good place to introduce brute force guard, blockade and failures limit?

	Rule: 1. Guarding authentication process depending on the brute force block	

		Background: 
		Given a user authenticates from the same IP address every time
		And the failures count limit is set to 3
		
		# todo zrób tu jeden wielki outline. Zależność IP od blokady (ważna lub nie), licznika, a na wstepie podaj 

		Scenario Outline: Positive (no blockade, failures count below the limit)
		Given no blockade is set for the IP
		And failures count for the IP equals to <failures_count>
		When the user authenticates
		Then the brute force guard passes lets the authentication through
		      Examples:
			| failures_count |
			| 0 |
			| 1 |
			| 2 |

		Scenario: Negative (failures count hit the limit)
		Given no blockade is set for the IP
		And failures count for the IP equals to 3
		When the user authenticates
		Then the brute force guard passes block the authentication

		Scenario: Negative (blockade is active)
		Given the IP is blocked
		And failures count for the IP equals to 3
		When the user authenticates
		Then the brute force guard passes block the authentication
		
		Scenario: Negative (blockade has expired, but the record exists in the database)
		Given the IP is blocked
		And failures count for the IP equals to 3
		When the user authenticates
		Then the brute force guard passes block the authentication
