Feature: generate session

	Background: This feature comes in play only when the authentication passes.
	
		Rule: session tokens are generated after successful authentication.
	
			Scenario: generate session tokens
			When the authentication passes
			Then the system generates a new session
