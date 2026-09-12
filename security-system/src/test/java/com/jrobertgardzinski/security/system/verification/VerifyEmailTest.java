package com.jrobertgardzinski.security.system.verification;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.repository.EmailVerificationRepository;
import com.jrobertgardzinski.security.domain.vo.token.VerificationToken;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import net.jqwik.api.Example;
import net.jqwik.api.Label;
import net.jqwik.api.lifecycle.BeforeTry;
import org.mockito.Mockito;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

@Epic("Use case")
@Feature("Verify email")
class VerifyEmailTest {

    private static final VerificationToken TOKEN = new VerificationToken("verification-token");
    private static final Email EMAIL = Email.of("user@example.com");

    private static final Duration TTL = Duration.ofHours(48);
    private static final LocalDateTime NOW = LocalDateTime.of(2026, 9, 12, 12, 0);
    private static final Clock CLOCK = Clock.fixed(NOW.toInstant(ZoneOffset.UTC), ZoneOffset.UTC);

    private EmailVerificationRepository repository;
    private VerifyEmail verifyEmail;

    @BeforeTry
    void init() {
        repository = Mockito.mock(EmailVerificationRepository.class);
        verifyEmail = new VerifyEmail(repository, TTL, CLOCK);
    }

    @Example
    @Label("A matching token verifies the address")
    void matching_token_verifies() {
        Mockito.when(repository.completeVerification(TOKEN)).thenReturn(pending(NOW.minusHours(1)));

        VerifyEmailResult result = verifyEmail.execute(TOKEN);

        assertEquals(new VerifyEmailResult.Verified(EMAIL), result);
    }

    @Example
    @Label("A link older than the window is rejected — and answered exactly like an unknown one")
    void an_expired_link_no_longer_verifies() {
        Mockito.when(repository.completeVerification(TOKEN)).thenReturn(pending(NOW.minus(TTL).minusMinutes(1)));

        // it verified an address for ever before this: the row carried no date at all, so a link
        // from a year ago was as good as one from a minute ago — and this is the address nobody is
        // watching, by definition
        assertInstanceOf(VerifyEmailResult.Rejected.class, verifyEmail.execute(TOKEN));
    }

    @Example
    @Label("A link at the very edge of the window still works")
    void the_edge_of_the_window_is_inside_it() {
        Mockito.when(repository.completeVerification(TOKEN)).thenReturn(pending(NOW.minus(TTL)));

        assertInstanceOf(VerifyEmailResult.Verified.class, verifyEmail.execute(TOKEN));
    }

    private static Optional<EmailVerificationRepository.PendingVerification> pending(LocalDateTime requestedAt) {
        return Optional.of(new EmailVerificationRepository.PendingVerification(EMAIL, requestedAt));
    }

    @Example
    @Label("An unknown token is rejected")
    void unknown_token_is_rejected() {
        Mockito.when(repository.completeVerification(TOKEN)).thenReturn(Optional.empty());

        assertInstanceOf(VerifyEmailResult.Rejected.class, verifyEmail.execute(TOKEN));
    }
}
