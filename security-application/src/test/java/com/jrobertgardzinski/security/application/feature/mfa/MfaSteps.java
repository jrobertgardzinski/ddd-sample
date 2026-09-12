package com.jrobertgardzinski.security.application.feature.mfa;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.password.domain.HashedPassword;
import com.jrobertgardzinski.password.domain.PlaintextPassword;
import com.jrobertgardzinski.security.application.feature.support.CapturingCodeChannel;
import com.jrobertgardzinski.security.application.feature.support.FakeHashAlgorithm;
import com.jrobertgardzinski.security.application.feature.support.InMemoryAuthenticationBlockRepository;
import com.jrobertgardzinski.security.application.feature.support.InMemoryAuthorizationDataRepository;
import com.jrobertgardzinski.security.application.feature.support.InMemoryEmailVerificationRepository;
import com.jrobertgardzinski.security.application.feature.support.InMemoryEnrolledFactorRepository;
import com.jrobertgardzinski.security.application.feature.support.InMemoryEnrolmentChallengeStore;
import com.jrobertgardzinski.security.application.feature.support.InMemoryPendingAuthenticationStore;
import com.jrobertgardzinski.security.application.feature.support.InMemoryRejectedAuthenticationRepository;
import com.jrobertgardzinski.security.application.feature.support.InMemoryUserRepository;
import com.jrobertgardzinski.security.config.bruteforce.BruteForceConfig;
import com.jrobertgardzinski.security.config.mfa.ChallengeCodeConfig;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.port.AccessTokenMint;
import com.jrobertgardzinski.security.domain.vo.AccessTokenValidityInHours;
import com.jrobertgardzinski.security.domain.vo.AuthenticationRequest;
import com.jrobertgardzinski.security.domain.vo.FactorType;
import com.jrobertgardzinski.security.domain.vo.IpAddress;
import com.jrobertgardzinski.security.domain.vo.RefreshTokenValidityInHours;
import com.jrobertgardzinski.security.domain.vo.SessionTokensConfig;
import com.jrobertgardzinski.security.domain.vo.Source;
import com.jrobertgardzinski.security.system.authentication.Authentication;
import com.jrobertgardzinski.security.system.authentication.AuthenticationFactory;
import com.jrobertgardzinski.security.system.authentication.AuthenticationResult;
import com.jrobertgardzinski.security.system.authentication.ContinueAuthentication;
import com.jrobertgardzinski.security.system.authentication.ContinueAuthenticationResult;
import com.jrobertgardzinski.security.system.mfa.CodeFactor;
import com.jrobertgardzinski.security.system.mfa.EnrolFactor;
import com.jrobertgardzinski.security.system.mfa.FactorRegistry;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * Application-level glue for {@code mfa.feature}: the chain use cases driven directly. An e-mail
 * factor is enrolled over a capturing code channel (so the "mailed" code can be read back), then a
 * sign-in is walked from the password step through the factor step to a session. The identity
 * hasher and code hasher are transparent test doubles — the crypto is tested elsewhere; here the
 * chain's behaviour is under test.
 */
public class MfaSteps {

    private static final String PASSWORD = "StrongPassword1!";
    private static final Source SOURCE = Source.of(new IpAddress("192.168.0.1"));
    private static final SessionTokensConfig SESSION_TOKENS_CONFIG =
            new SessionTokensConfig(new RefreshTokenValidityInHours(24), new AccessTokenValidityInHours(1));

    private final Clock clock = Clock.fixed(Instant.parse("2026-07-05T10:00:00Z"), ZoneOffset.UTC);
    private final FakeHashAlgorithm hashAlgorithm = new FakeHashAlgorithm();
    private final InMemoryUserRepository users = new InMemoryUserRepository();
    private final InMemoryEmailVerificationRepository verifications = new InMemoryEmailVerificationRepository(java.time.Clock.systemUTC());
    private final InMemoryAuthorizationDataRepository sessions = new InMemoryAuthorizationDataRepository(clock);
    private final InMemoryRejectedAuthenticationRepository rejections = new InMemoryRejectedAuthenticationRepository();
    private final InMemoryAuthenticationBlockRepository blocks = new InMemoryAuthenticationBlockRepository();
    private final InMemoryEnrolledFactorRepository enrolledFactors = new InMemoryEnrolledFactorRepository();
    private final InMemoryPendingAuthenticationStore pendingStore = new InMemoryPendingAuthenticationStore();
    private final InMemoryEnrolmentChallengeStore enrolmentStore = new InMemoryEnrolmentChallengeStore();
    private final CapturingCodeChannel emailChannel = new CapturingCodeChannel(FactorType.EMAIL_CODE);
    private final com.jrobertgardzinski.security.application.feature.support.InMemoryRecoveryCodeRepository
            recoveryCodes = new com.jrobertgardzinski.security.application.feature.support.InMemoryRecoveryCodeRepository();

    private final FactorRegistry registry = new FactorRegistry(List.of(
            new CodeFactor(emailChannel, raw -> "hash:" + raw, ChallengeCodeConfig.withDefaults(), clock)));
    private final EnrolFactor enrolFactor = new EnrolFactor(registry, enrolledFactors, enrolmentStore);
    private final com.jrobertgardzinski.security.system.mfa.GenerateRecoveryCodes generateRecoveryCodes =
            new com.jrobertgardzinski.security.system.mfa.GenerateRecoveryCodes(
                    recoveryCodes, raw -> "hash:" + raw,
                    com.jrobertgardzinski.security.config.mfa.RecoveryCodeConfig.withDefaults());

    private final AuthenticationFactory.AuthenticationUseCases useCases = AuthenticationFactory.assemble(
            users, verifications, rejections, blocks, sessions, hashAlgorithm,
            BruteForceConfig.builder().build(), SESSION_TOKENS_CONFIG, clock,
            () -> 5, AccessTokenMint.RANDOM,
            enrolledFactors,
            new com.jrobertgardzinski.security.system.mfa.MfaChain(registry, ChallengeCodeConfig.withDefaults(),
                    recoveryCodes, raw -> "hash:" + raw, clock, 10),
            pendingStore);
    private final Authentication authentication = useCases.authentication();
    private final ContinueAuthentication continueAuthentication = useCases.continueAuthentication();

    private String email;
    private AuthenticationResult authResult;
    private ContinueAuthenticationResult factorResult;
    private List<String> generatedRecoveryCodes;
    private String spentRecoveryCode;

    @Given("a verified USER {string} with password {string}")
    public void aVerifiedUser(String email, String password) {
        this.email = email;
        users.save(new User(Email.of(email), hashAlgorithm.hash(PlaintextPassword.of(password))));
        verifications.markVerified(Email.of(email));
    }

    @Given("the USER has enrolled the e-mail FACTOR")
    public void enrolledEmailFactor() {
        enrolFactor.start(Email.of(email), FactorType.EMAIL_CODE, email);
        EnrolFactor.Result result = enrolFactor.confirm(Email.of(email), FactorType.EMAIL_CODE, mailedCode());
        assertInstanceOf(EnrolFactor.Result.Enrolled.class, result, "failed to seed the e-mail factor");
    }

    @Given("the USER has AUTHENTICATED the password step")
    public void authenticatedPasswordStep() {
        authenticateWithPassword();
        assertInstanceOf(AuthenticationResult.MfaRequired.class, authResult, "the password step did not reach MFA");
    }

    @When("the USER AUTHENTICATES with the correct password")
    public void authenticateWithPassword() {
        authResult = authentication.execute(new AuthenticationRequest(
                SOURCE, Email.of(email), PlaintextPassword.of(PASSWORD)));
    }

    @When("the USER submits the mailed CODE")
    public void submitMailedCode() {
        factorResult = continueAuthentication.execute(ticket(), mailedCode());
    }

    @When("the USER submits a wrong CODE")
    public void submitWrongCode() {
        factorResult = continueAuthentication.execute(ticket(), "000000");
    }

    @Given("the USER has GENERATED RECOVERY CODES")
    public void generatedRecoveryCodes() {
        generatedRecoveryCodes = generateRecoveryCodes.execute(Email.of(email));
    }

    @When("the USER submits a RECOVERY CODE instead of the mailed CODE")
    public void submitRecoveryCode() {
        spentRecoveryCode = generatedRecoveryCodes.get(0);
        factorResult = continueAuthentication.execute(ticket(), spentRecoveryCode);
    }

    @Given("the USER has signed in with a RECOVERY CODE once already")
    public void signedInWithRecoveryCodeOnce() {
        authenticatedPasswordStep();
        submitRecoveryCode();
        assertInstanceOf(ContinueAuthenticationResult.Completed.class, factorResult,
                "the first recovery-code sign-in should have succeeded");
    }

    @When("the USER submits the same RECOVERY CODE again")
    public void submitSameRecoveryCodeAgain() {
        factorResult = continueAuthentication.execute(ticket(), spentRecoveryCode);
    }

    @Then("a FACTOR CODE is required, not a session")
    public void aFactorCodeIsRequired() {
        assertInstanceOf(AuthenticationResult.MfaRequired.class, authResult);
    }

    @Then("the USER is signed in")
    public void userIsSignedIn() {
        assertInstanceOf(ContinueAuthenticationResult.Completed.class, factorResult);
    }

    @Then("the sign-in is refused and a session is not issued")
    public void signInRefused() {
        assertInstanceOf(ContinueAuthenticationResult.WrongProof.class, factorResult);
    }

    private String ticket() {
        return ((AuthenticationResult.MfaRequired) authResult).ticket();
    }

    private String mailedCode() {
        return emailChannel.lastCodeFor(email);
    }
}
