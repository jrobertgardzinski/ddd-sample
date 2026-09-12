package com.jrobertgardzinski;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.password.domain.PlaintextPassword;
import com.jrobertgardzinski.security.domain.vo.IpAddress;
import com.jrobertgardzinski.security.system.registration.Register;
import com.jrobertgardzinski.email.config.CanRegisterConfig;
import com.jrobertgardzinski.email.domain.DomainPart;
import com.jrobertgardzinski.password.policy.PasswordPolicy;
import com.jrobertgardzinski.security.system.registration.RegisterResult;
import com.jrobertgardzinski.security.system.throttle.SourceThrottle;
import com.jrobertgardzinski.security.system.verification.RequestEmailVerification;
import jakarta.inject.Named;
import com.jrobertgardzinski.security.domain.port.RegistrationNoticeNotifier;
import com.jrobertgardzinski.security.domain.repository.EmailVerificationRepository;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import io.micronaut.http.annotation.Post;

import java.util.List;
import java.util.Map;

/**
 * HTTP entry point for registration. This adapter drives the exact same {@link Register}
 * use case that the application-level Cucumber glue drives directly — "same behaviour,
 * different entry point". The HTTP contract:
 * <ul>
 *   <li>{@code Registered}        &rarr; 201 Created, {@code {"status": "CHECK_YOUR_MAILBOX"}};
 *       a verification link is e-mailed — sign-in stays blocked until the address is verified</li>
 *   <li>{@code Rejected}          &rarr; 422 Unprocessable Entity,
 *       {@code {"emailErrors": [{"CODE": parameter}], "passwordErrors": [{"CODE": parameter}]}} —
 *       both channels speak ONE shape: one code per broken rule, valued by the parameter in force
 *       for this very attempt ({@code {"MIN_LENGTH_NOT_MET": 12}},
 *       {@code {"NOT_A_COMPANY_DOMAIN": ["acme.com"]}}) or {@code true} where the rule has none.
 *       Both policies are configuration, so a bare code would leave the caller guessing what the
 *       minimum was, or which domains an employee may register from</li>
 *   <li>{@code EmailAlreadyTaken} &rarr; the same 201 and the same body as {@code Registered}
 *       (anti-enumeration: the wire never confirms an account exists). What differs is the mail,
 *       readable only by the address owner: a still-unverified account gets a fresh verification
 *       link (they probably lost the first one), a verified one gets a "you already have an
 *       account" notice.</li>
 * </ul>
 * 422 (not 400): the JSON is well-formed; the failure is semantic validation of the values.
 * Validation errors may reveal that an address is malformed, but never whether it is taken.
 */
// controllers do blocking work (JDBC, the mail service's HTTP client) — keep it off the event loop
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/register")
public class SecurityController {

    /** The one body every non-rejected registration answers with — fresh or taken alike. */
    static final Map<String, Object> CHECK_YOUR_MAILBOX = Map.of("status", "CHECK_YOUR_MAILBOX");

    private final Register register;
    private final RequestEmailVerification requestEmailVerification;
    private final TransactionBoundary transactionBoundary;
    private final SourceThrottle registrationThrottle;
    private final ClientIpResolver clientIpResolver;
    private final EmailVerificationRepository emailVerifications;
    private final RegistrationNoticeNotifier registrationNoticeNotifier;

    public SecurityController(Register register, RequestEmailVerification requestEmailVerification,
                              TransactionBoundary transactionBoundary,
                              @Named("registration") SourceThrottle registrationThrottle,
                              ClientIpResolver clientIpResolver,
                              EmailVerificationRepository emailVerifications,
                              RegistrationNoticeNotifier registrationNoticeNotifier) {
        this.register = register;
        this.requestEmailVerification = requestEmailVerification;
        this.transactionBoundary = transactionBoundary;
        this.registrationThrottle = registrationThrottle;
        this.clientIpResolver = clientIpResolver;
        this.emailVerifications = emailVerifications;
        this.registrationNoticeNotifier = registrationNoticeNotifier;
    }

    @Post(consumes = MediaType.APPLICATION_JSON, produces = MediaType.APPLICATION_JSON)
    public HttpResponse<Map<String, Object>> register(HttpRequest<?> request, @Body Map<String, String> body) {
        // guard before the expensive work: registration hashes a password and creates an account
        IpAddress source = clientIpResolver.resolve(request);
        SourceThrottle.Decision decision = registrationThrottle.check(source);
        if (!decision.allowed()) {
            return HttpResponse.<Map<String, Object>>status(HttpStatus.TOO_MANY_REQUESTS)
                    .header("Retry-After", String.valueOf(decision.retryAfterSeconds()))
                    .body(Refusal.alsoAsError("TOO_MANY_REGISTRATIONS"));
        }

        String email = body.get("email");
        String password = body.get("password");

        RegisterResult result = transactionBoundary.execute(
                () -> register.execute(() -> Email.of(email), () -> PlaintextPassword.of(password)));

        return switch (result) {
            case RegisterResult.Registered registered -> {
                // sign-in requires a verified address, so onboarding starts the verification here
                transactionBoundary.execute(() -> {
                    requestEmailVerification.execute(Email.of(email));
                    return null;
                });
                yield HttpResponse.<Map<String, Object>>created(CHECK_YOUR_MAILBOX);
            }
            case RegisterResult.Rejected rejected ->
                    HttpResponse.<Map<String, Object>>status(HttpStatus.UNPROCESSABLE_ENTITY)
                            .body(Map.of(
                                    "emailErrors", emailErrors(rejected.emailErrors().codes(), rejected.emailPolicy()),
                                    "passwordErrors", passwordErrors(rejected.passwordErrors().codes(), rejected.passwordPolicy())));
            case RegisterResult.EmailAlreadyTaken alreadyTaken -> {
                // quiet refusal: the caller sees a fresh-looking registration; the address owner
                // is told by mail — a lost-mail re-register gets a fresh link, a real account a notice
                transactionBoundary.execute(() -> {
                    if (emailVerifications.isVerified(alreadyTaken.email())) {
                        registrationNoticeNotifier.sendAlreadyRegistered(alreadyTaken.email());
                    } else {
                        requestEmailVerification.execute(alreadyTaken.email());
                    }
                    return null;
                });
                yield HttpResponse.<Map<String, Object>>created(CHECK_YOUR_MAILBOX);
            }
        };
    }

    /**
     * One entry per failed email rule, keyed by its code and valued by the email policy in force
     * for this attempt — the same shape as the password channel, so a client renders both with one
     * piece of code. Only the company rule carries a parameter: the domains an employee MAY
     * register from are the hint the caller needs. The blocked and disposable rules stay
     * {@code true}: those lists are denylists, and enumerating them would only tell an abuser
     * which domains to try next; the caller already knows which domain they typed.
     */
    static List<Map<String, Object>> emailErrors(List<String> codes, CanRegisterConfig policy) {
        return codes.stream().map(code -> Map.<String, Object>of(code, switch (code) {
            case "NOT_A_COMPANY_DOMAIN" -> policy.companyDomains().values().stream()
                    .map(DomainPart::value).sorted().toList();
            default -> Boolean.TRUE;
        })).toList();
    }

    /**
     * One entry per failed password rule, keyed by its code, valued by the rule's parameter in
     * force for this attempt — or {@code true} where the rule has none (digit, uppercase,
     * lowercase say everything in their code already).
     */
    static List<Map<String, Object>> passwordErrors(List<String> codes, PasswordPolicy policy) {
        return codes.stream().map(code -> Map.<String, Object>of(code, switch (code) {
            case "MIN_LENGTH_NOT_MET" -> policy.minLength().value();
            case "SPECIAL_CHAR_REQUIRED" -> policy.specialChars().value();
            default -> Boolean.TRUE;
        })).toList();
    }
}
