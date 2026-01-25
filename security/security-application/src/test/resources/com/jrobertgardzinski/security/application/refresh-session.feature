Feature: refresh session

	Background: Extending a user session requires refreshing a token, which is valid for some time.
	
		Rule: 1. Refresh token has to be valid
		
			Scenario: Positive
			
			Given a user has an active refresh token
			When the user passes refresh and authentication tokens
			Then the system removes passed tokens from the database
			And the user gets a pair of new tokens
			
			Scenario: Passing invalid tokens
			
			Given a user has an inactive refresh token
			When the user passes refresh and authentication tokens
			Then the system responds with the RefreshTokenExpiredEvent error
			
			Scenario: Passing invalid tokens twice
			
			Given a user has an inactive refresh token
			When the user passes refresh and authentication tokens twice
			Then the system responds with the NoRefreshTokenFoundEvent error
