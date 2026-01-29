# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Build entire project
mvn clean install

# Run all tests
mvn test

# Run tests for a specific module
mvn test -pl security/security-application

# Run a single test class
mvn test -pl security/security-application -Dtest=RegistrationTest

# Run Cucumber tests (via RunCucumberTest suite)
mvn test -pl security/security-application -Dtest=RunCucumberTest
```

## Architecture

This is a DDD (Domain-Driven Design) sample project using a multi-module Maven structure with Java 21.

### Module Hierarchy

```
ddd-sample (parent)
├── test-starter          # Shared test dependencies (JUnit 5, Mockito, Hamcrest)
├── security-domain-model # Value objects (Email, Password, Token, etc.)
├── security-domain-persistence # Entities, aggregates, and repository interfaces
├── hash-algorithm/
│   ├── hash-algorithm-domain  # Port interface (HashAlgorithmPort)
│   └── hash-algorithm-argon2  # Argon2 adapter implementation
└── security/
    ├── security-domain-event  # Domain events (Registration, Authentication, etc.)
    ├── security-application   # Application services and features with Cucumber tests
    └── security-infrastructure # Entry point (App.java)
```

### DDD Layer Pattern

The project follows a strict layering approach:
- **Value Objects (vo package)**: Immutable types with validation in constructors (e.g., `Email`, `PlainTextPassword`)
- **Entities**: Domain objects with identity (e.g., `User`, `AuthenticationBlock`)
- **Repositories**: Interfaces in `security-domain-persistence`, implementations elsewhere
- **Services/Features**: Application logic in `security-application` (e.g., `Register`, `Authenticate`)
- **Events**: Outcomes of operations as sealed types (e.g., `RegistrationPassedEvent`, `RegistrationFailedEvent`)
- **Ports/Adapters**: External dependencies abstracted via ports (e.g., `HashAlgorithmPort`)

### Key Patterns

- Entities use dedicated value object classes for all fields (never primitive types directly)
- External resources use String fields prefixed with "ext" containing resource URIs
- Application features return domain events indicating success/failure
- Cucumber BDD tests in `security-application` define behavior specifications
- `SecurityService` orchestrates features and handles authentication flow with brute force protection
