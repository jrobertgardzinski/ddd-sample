package com.jrobertgardzinski.security.infrastructure.persistence;

import com.jrobertgardzinski.CapturingEmailVerificationNotifier;
import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.email.domain.NormalizedEmail;
import com.jrobertgardzinski.security.domain.port.EmailVerificationNotifier;
import com.jrobertgardzinski.security.domain.repository.EmailVerificationRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.token.VerificationToken;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * An account and the mail that makes it usable are written together, or not at all.
 *
 * <p>They used to be two transactions: the account committed, and the verification was started
 * afterwards. Anything that went wrong in between — the service being stopped, the outbox append
 * failing — left an account nobody was ever sent a link for, while every sign-in demands a verified
 * address. It is a real rollback of a real table, so only PostgreSQL can settle it: the in-memory
 * repositories have no transaction to roll back, and would report this as fixed whatever the
 * controller does.
 *
 * <p>The mail is made to fail on purpose, because that is the only half of the pair a test can
 * reach. Putting the two writes back into separate boundaries turns this red.
 */
@Testcontainers(disabledWithoutDocker = true)
class RegistrationAtomicityTest {

    private static final String ADDRESS = "atomic-registration@example.com";

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18-alpine");

    static EmbeddedServer server;
    static BlockingHttpClient client;

    @BeforeAll
    static void startServer() {
        server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "datasources.default.url", POSTGRES.getJdbcUrl(),
                "datasources.default.username", POSTGRES.getUsername(),
                "datasources.default.password", POSTGRES.getPassword(),
                "datasources.default.driver-class-name", "org.postgresql.Driver",
                "datasources.default.dialect", "POSTGRES",
                "flyway.datasources.default.enabled", true,
                "test.verification-mail.fails", true), "test");
        client = server.getApplicationContext()
                .createBean(HttpClient.class, server.getURL()).toBlocking();
    }

    @AfterAll
    static void stopServer() {
        if (client != null) {
            client.close();
        }
        if (server != null) {
            server.close();
        }
    }

    @Test
    @DisplayName("a registration whose verification mail fails leaves no account behind")
    void the_account_and_its_verification_commit_together() {
        assertThatThrownBy(() -> client.exchange(HttpRequest.POST("/register", Map.of(
                "email", ADDRESS, "password", "StrongPassword1!"))))
                .as("the mail could not be written, so the request did not succeed")
                .isInstanceOf(HttpClientResponseException.class)
                .satisfies(refused -> assertThat(((HttpClientResponseException) refused).getStatus().getCode())
                        .as("and it failed for THIS reason — a 422 would mean the registration never"
                                + " reached the mail at all, and the test would prove nothing")
                        .isEqualTo(500));

        UserRepository users = server.getApplicationContext().getBean(UserRepository.class);
        EmailVerificationRepository verifications =
                server.getApplicationContext().getBean(EmailVerificationRepository.class);

        assertThat(users.findBy(Email.of(ADDRESS)))
                .as("an account with no verification mail is an account its owner can never sign"
                        + " into and can never be given, because the address is now taken")
                .isEmpty();
        assertThat(users.existsBy(NormalizedEmail.of(Email.of(ADDRESS)))).isFalse();
        assertThat(verifications.isVerified(Email.of(ADDRESS))).isFalse();
    }
}

/** The one half of the pair a test can make fail: appending the mail. */
@Singleton
@Requires(property = "test.verification-mail.fails", value = "true")
@Replaces(CapturingEmailVerificationNotifier.class)
class ExplodingEmailVerificationNotifier implements EmailVerificationNotifier {

    @Override
    public void sendVerificationLink(Email email, VerificationToken token) {
        throw new IllegalStateException("the outbox is unreachable");
    }
}
