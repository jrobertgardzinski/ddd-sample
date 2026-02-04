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
- **Value Objects (vo package)**: Immutable types with validation in constructors (e.g., `Email`, `PlaintextPassword`)
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

## Notes / Ideas for future discussion

- **Policy versioning case study**: "180 wrong questions in driving license exam database"
  - Scenario: policy (exam questions) had errors, some examinees failed unfairly
  - Need to identify affected users and compensate (refund + free retry)
  - Analyze how to model this: policy versioning, affected user detection, compensation events

- **Changelog tooling** - evaluate and pick one:
  - [Conventional Commits](https://www.conventionalcommits.org/) - commit message standard (`feat:`, `fix:`, `breaking:`)
  - [git-cliff](https://git-cliff.org/) - Rust-based, highly configurable, generates from conventional commits
  - [standard-version](https://github.com/conventional-changelog/standard-version) - npm, auto-bumps version + generates CHANGELOG.md
  - [release-please](https://github.com/googleapis/release-please) - Google's tool, GitHub Action friendly
  - [Keep a Changelog](https://keepachangelog.com/) - manual format standard (if you prefer hand-written changelogs)
  - For Java/Maven: consider [maven-git-changelog-plugin](https://github.com/jakubplichta/git-changelog-maven-plugin)

- **BDD testing strategy across layers** - shared feature files, separate step definitions:
  ```
  ┌─────────────────────────────────────────┐
  │  UI Layer                               │  Cypress/Playwright + Cucumber
  │  (microfrontends integration)           │  Step definitions: TypeScript/JS
  ├─────────────────────────────────────────┤
  │  Infrastructure Layer                   │  Spring + Cucumber
  │  (HTTP API, messaging)                  │  Step definitions: Java
  ├─────────────────────────────────────────┤
  │  Application Layer                      │  JUnit + Cucumber (current)
  │  (use cases, domain logic)              │  Step definitions: Java
  └─────────────────────────────────────────┘
  ```
  - Single `.feature` files shared across all layers (single source of truth)
  - Each layer implements its own step definitions
  - Enables testing the same behavior at different abstraction levels
  - Microfrontend framework candidates: React, Vue, Angular (all support Module Federation)
