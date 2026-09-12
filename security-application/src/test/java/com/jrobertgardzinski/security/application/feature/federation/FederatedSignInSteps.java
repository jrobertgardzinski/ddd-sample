package com.jrobertgardzinski.security.application.feature.federation;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.password.domain.HashedPassword;
import com.jrobertgardzinski.password.domain.PlaintextPassword;
import com.jrobertgardzinski.security.application.feature.support.FakeHashAlgorithm;
import com.jrobertgardzinski.security.application.feature.support.InMemoryAuthorizationDataRepository;
import com.jrobertgardzinski.security.application.feature.support.InMemoryEmailVerificationRepository;
import com.jrobertgardzinski.security.application.feature.support.InMemoryUserRepository;
import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.port.AccessTokenMint;
import com.jrobertgardzinski.security.domain.repository.FederatedIdentityRepository;
import com.jrobertgardzinski.security.domain.vo.AccessTokenValidityInHours;
import com.jrobertgardzinski.security.domain.vo.ProviderIdentity;
import com.jrobertgardzinski.security.domain.vo.RefreshTokenValidityInHours;
import com.jrobertgardzinski.security.domain.vo.SessionFamily;
import com.jrobertgardzinski.security.domain.vo.SessionTokensConfig;
import com.jrobertgardzinski.security.system.federation.FederatedSignIn;
import com.jrobertgardzinski.security.system.federation.FederatedSignInResult;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import java.time.Clock;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Application-level glue for {@code federated-sign-in.feature}: the {@link FederatedSignIn} use
 * case driven directly, with the OAuth dance already behind us — the scenarios start from what
 * the provider asserted (a {@link ProviderIdentity}), which is exactly the use case's boundary.
 */
public class FederatedSignInSteps {

    private final InMemoryUserRepository users = new InMemoryUserRepository();
    private final InMemoryEmailVerificationRepository verifications = new InMemoryEmailVerificationRepository(java.time.Clock.systemUTC());
    private final InMemoryAuthorizationDataRepository sessions = new InMemoryAuthorizationDataRepository(Clock.systemUTC());
    private final FakeHashAlgorithm hashAlgorithm = new FakeHashAlgorithm();
    private final Map<String, String> links = new HashMap<>();
    private final FederatedIdentityRepository identities = new FederatedIdentityRepository() {
        public Optional<Email> findUserBy(String provider, String subject) {
            return Optional.ofNullable(links.get(provider + "|" + subject)).map(Email::of);
        }

        public void link(String provider, String subject, Email userEmail) {
            links.put(provider + "|" + subject, userEmail.value());
        }

        public void unlinkAll(Email userEmail) {
            links.values().removeIf(userEmail.value()::equals);
        }

        public void relinkAll(Email fromEmail, Email toEmail) {
            links.replaceAll((key, email) -> fromEmail.value().equals(email) ? toEmail.value() : email);
        }
    };
    private final com.jrobertgardzinski.security.application.feature.support.InMemoryPasswordlessAccountRepository passwordless =
            new com.jrobertgardzinski.security.application.feature.support.InMemoryPasswordlessAccountRepository();
    // a real e-mail factor over a capturing channel, so a scenario can enrol one and prove the
    // federated sign-in then owes it
    private final com.jrobertgardzinski.security.application.feature.support.InMemoryEnrolledFactorRepository enrolledFactors =
            new com.jrobertgardzinski.security.application.feature.support.InMemoryEnrolledFactorRepository();
    private final com.jrobertgardzinski.security.application.feature.support.CapturingCodeChannel emailChannel =
            new com.jrobertgardzinski.security.application.feature.support.CapturingCodeChannel(
                    com.jrobertgardzinski.security.domain.vo.FactorType.EMAIL_CODE);
    private final com.jrobertgardzinski.security.system.mfa.FactorRegistry registry =
            new com.jrobertgardzinski.security.system.mfa.FactorRegistry(java.util.List.of(
                    new com.jrobertgardzinski.security.system.mfa.CodeFactor(emailChannel, raw -> "h:" + raw,
                            com.jrobertgardzinski.security.config.mfa.ChallengeCodeConfig.withDefaults(), Clock.systemUTC())));
    private final com.jrobertgardzinski.security.system.mfa.EnrolFactor enrolFactor =
            new com.jrobertgardzinski.security.system.mfa.EnrolFactor(registry, enrolledFactors,
                    new com.jrobertgardzinski.security.application.feature.support.InMemoryEnrolmentChallengeStore());
    private final FederatedSignIn federatedSignIn = new FederatedSignIn(
            identities, users, verifications, sessions, hashAlgorithm,
            new SessionTokensConfig(new RefreshTokenValidityInHours(24), new AccessTokenValidityInHours(1)),
            Clock.systemUTC(), AccessTokenMint.RANDOM, passwordless, enrolledFactors,
            new com.jrobertgardzinski.security.system.mfa.MfaChain(registry,
                    com.jrobertgardzinski.security.config.mfa.ChallengeCodeConfig.withDefaults(),
                    new com.jrobertgardzinski.security.application.feature.support.InMemoryRecoveryCodeRepository(),
                    raw -> "hash:" + raw, Clock.systemUTC(), 10),
            new com.jrobertgardzinski.security.application.feature.support.InMemoryPendingAuthenticationStore());

    private FederatedSignInResult result;

    @io.cucumber.java.en.Given("the ACCOUNT {string} has enrolled an e-mail FACTOR")
    public void hasEnrolledFactor(String email) {
        enrolFactor.start(Email.of(email), com.jrobertgardzinski.security.domain.vo.FactorType.EMAIL_CODE, email);
        enrolFactor.confirm(Email.of(email), com.jrobertgardzinski.security.domain.vo.FactorType.EMAIL_CODE,
                emailChannel.lastCodeFor(email));
    }

    @io.cucumber.java.en.Then("the SIGN IN needs a further FACTOR")
    public void needsAFurtherFactor() {
        assertInstanceOf(FederatedSignInResult.MfaRequired.class, result);
    }

    @Given("a local ACCOUNT {string} with a verified email and the password {string}")
    public void aVerifiedLocalAccount(String email, String password) {
        users.save(new User(Email.of(email), hashAlgorithm.hash(PlaintextPassword.of(password))));
        verifications.markVerified(Email.of(email));
    }

    @Given("a local ACCOUNT {string} with an unverified email and the password {string}")
    public void anUnverifiedLocalAccount(String email, String password) {
        users.save(new User(Email.of(email), hashAlgorithm.hash(PlaintextPassword.of(password))));
    }

    @Given("a DELETION is running for {string}")
    public void aDeletionIsRunning(String email) {
        users.markPendingDeletion(Email.of(email));
    }

    @Then("the ACCOUNT {string} is still unverified")
    public void stillUnverified(String email) {
        assertFalse(verifications.isVerified(Email.of(email)),
                "a refused sign-in must not mark the address verified");
    }

    @Then("no PROVIDER identity is linked to {string}")
    public void noIdentityLinked(String email) {
        // the whole point of the ordering: claimByEmail WRITES (password wiped, sessions revoked,
        // address verified, identity linked) and used to run BEFORE the pending-deletion check, so
        // an account on its way out got a provider identity welded onto it while sign-in was refused
        assertFalse(links.containsValue(email),
                "a refused sign-in must leave no provider identity behind");
    }

    @Given("the ACCOUNT {string} holds an active session")
    public void anActiveSession(String email) {
        sessions.create(SessionTokens.createFor(Email.of(email),
                new SessionTokensConfig(new RefreshTokenValidityInHours(24), new AccessTokenValidityInHours(1)),
                Clock.systemUTC()), SessionFamily.start());
        assertFalse(sessions.listActiveSessions(Email.of(email)).isEmpty(), "failed to seed a session");
    }

    /** The account as it stood after the FIRST contact — what "not a twin" is measured against. */
    private UUID accountBefore;

    @Given("the USER already SIGNED IN with a PROVIDER identity vouching for {string}")
    public void alreadySignedInWith(String email) {
        signIn(email, true);
        assertInstanceOf(FederatedSignInResult.SignedIn.class, result, "failed to seed the first sign-in");
        accountBefore = users.findBy(Email.of(email)).orElseThrow().id();
    }

    @When("the USER SIGNS IN with a PROVIDER identity vouching for {string}")
    public void signsInVouched(String email) {
        signIn(email, true);
    }

    @When("the USER SIGNS IN with a PROVIDER identity NOT vouching for {string}")
    public void signsInUnvouched(String email) {
        signIn(email, false);
    }

    @Then("the USER is SIGNED IN")
    public void isSignedIn() {
        assertInstanceOf(FederatedSignInResult.SignedIn.class, result);
    }

    @Then("the SIGN IN is refused")
    public void isRefused() {
        assertInstanceOf(FederatedSignInResult.Refused.class, result);
    }

    @Then("the ACCOUNT {string} exists, verified from birth")
    public void accountExistsVerified(String email) {
        assertTrue(users.findBy(Email.of(email)).isPresent(), "the account was not created");
        assertTrue(verifications.isVerified(Email.of(email)),
                "the provider's word replaces our mail loop — the account must be born verified");
    }

    /**
     * The twin check, in the scenario that is about twins.
     *
     * <p>It used to live inside the step above — which belongs to a DIFFERENT example, and which
     * performed a second sign-in of its own to have something to compare. So the scenario named
     * "not a twin" asserted only that somebody was signed in, and the assertion that gave it its
     * name ran somewhere else, on data that step had made up.
     */
    @Then("the ACCOUNT {string} is the one that already existed")
    public void theSameAccountAsBefore(String email) {
        assertNotNull(accountBefore, "nothing was signed in before this — the example is misread");
        assertEquals(accountBefore, users.findBy(Email.of(email)).orElseThrow().id(),
                "a repeat sign-in must reuse the account, not mint a twin: the address answers with"
                        + " a different account than it did a moment ago");
    }

    @Then("no ACCOUNT {string} exists")
    public void noAccountExists(String email) {
        assertTrue(users.findBy(Email.of(email)).isEmpty());
    }

    @Then("the password {string} still opens the ACCOUNT {string}")
    public void passwordStillWorks(String password, String email) {
        HashedPassword stored = users.findBy(Email.of(email)).orElseThrow().passwordHash();
        assertTrue(hashAlgorithm.verify(stored, PlaintextPassword.of(password)),
                "auto-linking must not touch the existing password");
    }

    @Then("the password {string} no longer opens the ACCOUNT {string}")
    public void passwordDied(String password, String email) {
        HashedPassword stored = users.findBy(Email.of(email)).orElseThrow().passwordHash();
        assertFalse(hashAlgorithm.verify(stored, PlaintextPassword.of(password)),
                "the squatter's unproven password must die with the takeover");
        assertNotEquals(password, stored.value(), "the replacement must be a fresh secret");
    }

    @Then("every previous session of {string} is revoked")
    public void sessionsRevoked(String email) {
        // the takeover revoked everything, then the sign-in itself opened exactly one new session
        assertEquals(1, sessions.listActiveSessions(Email.of(email)).size(),
                "only the takeover's own session may survive");
    }

    private void signIn(String email, boolean vouched) {
        result = federatedSignIn.execute(
                new ProviderIdentity("stub", "sub-" + email, Email.of(email), vouched));
    }
}
