package com.jrobertgardzinski.security.infrastructure.persistence;

import com.jrobertgardzinski.config.source.live.LiveConfigPort;
import com.jrobertgardzinski.config.source.live.SnapshotLiveConfigPort;
import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.email.domain.NormalizedEmail;
import com.jrobertgardzinski.password.domain.HashedPassword;
import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.entity.EnrolledFactor;
import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.repository.EmailAlreadyTakenException;
import com.jrobertgardzinski.security.domain.repository.EmailChangeRepository;
import com.jrobertgardzinski.security.domain.repository.EmailVerificationRepository;
import com.jrobertgardzinski.security.domain.repository.EnrolledFactorRepository;
import com.jrobertgardzinski.security.domain.repository.PasswordResetRepository;
import com.jrobertgardzinski.security.domain.repository.PasswordlessAccountRepository;
import com.jrobertgardzinski.security.domain.repository.RecoveryCodeRepository;
import com.jrobertgardzinski.security.domain.repository.RejectedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.AccessGrant;
import com.jrobertgardzinski.security.domain.vo.EmailChange;
import com.jrobertgardzinski.security.domain.vo.FactorType;
import com.jrobertgardzinski.security.domain.vo.AccessTokenValidityInHours;
import com.jrobertgardzinski.security.domain.vo.IpAddress;
import com.jrobertgardzinski.security.domain.vo.AttemptedAccount;
import com.jrobertgardzinski.security.domain.vo.LockoutSubject;
import com.jrobertgardzinski.security.domain.vo.Source;
import com.jrobertgardzinski.security.domain.vo.RefreshTokenValidityInHours;
import com.jrobertgardzinski.security.domain.vo.RejectedAuthenticationDetails;
import com.jrobertgardzinski.security.domain.vo.SessionFamily;
import com.jrobertgardzinski.security.domain.vo.SessionStatus;
import com.jrobertgardzinski.security.domain.vo.SessionTokensConfig;
import com.jrobertgardzinski.security.domain.vo.StoredSession;
import com.jrobertgardzinski.security.domain.vo.token.AccessToken;
import com.jrobertgardzinski.security.domain.vo.token.PasswordResetToken;
import com.jrobertgardzinski.security.domain.vo.token.RefreshToken;
import com.jrobertgardzinski.security.domain.vo.token.VerificationToken;
import io.micronaut.context.ApplicationContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import com.jrobertgardzinski.persistence.SecuritySettingsTable;
import com.jrobertgardzinski.password.config.MinLength;
import com.jrobertgardzinski.security.system.settings.SettingsRepository;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Drives the JDBC repository adapters against a real PostgreSQL (so the Micronaut Data mappings,
 * the snake_case columns, Flyway's schema and the refresh-token hashing are exercised for real).
 * Skipped automatically when no Docker is available. Beans are resolved by their domain port type:
 * a datasource is present, so the JDBC adapters win over the in-memory ones.
 */
@Testcontainers(disabledWithoutDocker = true)
class JdbcAdaptersTest {

    private static final SessionTokensConfig SESSION_CONFIG = new SessionTokensConfig(
            new RefreshTokenValidityInHours(24), new AccessTokenValidityInHours(1));

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18-alpine");

    static ApplicationContext context;

    @BeforeAll
    static void startContext() {
        context = ApplicationContext.run(Map.of(
                "datasources.default.url", POSTGRES.getJdbcUrl(),
                "datasources.default.username", POSTGRES.getUsername(),
                "datasources.default.password", POSTGRES.getPassword(),
                "datasources.default.driver-class-name", "org.postgresql.Driver",
                "datasources.default.dialect", "POSTGRES",
                "flyway.datasources.default.enabled", true));
    }

    @AfterAll
    static void stopContext() {
        if (context != null) {
            context.close();
        }
    }

    @Test
    void users_are_saved_found_and_deduplicated() {
        UserRepository users = context.getBean(UserRepository.class);
        Email email = Email.of("jdbc-user@example.com");
        User user = new User(email, new HashedPassword("argon2-hash"));

        users.save(user);

        assertThat(users.findBy(email)).get().extracting(User::id).isEqualTo(user.id());
        assertThat(users.existsBy(NormalizedEmail.of(email))).isTrue();
        assertThat(users.findBy(Email.of("nobody@example.com"))).isEmpty();
        assertThat(users.existsBy(NormalizedEmail.of(Email.of("nobody@example.com")))).isFalse();
    }

    @Test
    void rejected_attempts_are_counted_within_a_window_and_cleared() {
        RejectedAuthenticationRepository rejected = context.getBean(RejectedAuthenticationRepository.class);
        Source ip = new Source(new IpAddress("203.0.113.10"), "smoke-agent/1.0");
        LockoutSubject victim = new LockoutSubject(ip, AttemptedAccount.of(Email.of("victim@example.com")));
        LockoutSubject other = new LockoutSubject(ip, AttemptedAccount.of(Email.of("someone.else@example.com")));
        LocalDateTime at = LocalDateTime.now();
        rejected.create(new RejectedAuthenticationDetails(victim, at));
        rejected.create(new RejectedAuthenticationDetails(victim, at));
        rejected.create(new RejectedAuthenticationDetails(other, at));

        assertThat(rejected.countFailuresOnAccount(victim, at.minusMinutes(15)).count()).isEqualTo(2);
        assertThat(rejected.countFailuresOnAccount(victim, at.plusMinutes(1)).count()).isZero();
        // the ceiling sees every account this address missed on — that is what catches spraying
        assertThat(rejected.countFailuresFromSource(ip, at.minusMinutes(15)).count()).isEqualTo(3);

        // forgetting one pair leaves the rest of the address's record alone: it is other
        // people's business, and wiping it is what once made one good password an amnesty
        rejected.removeAllFor(victim);
        assertThat(rejected.countFailuresOnAccount(victim, at.minusMinutes(15)).count()).isZero();
        assertThat(rejected.countFailuresOnAccount(other, at.minusMinutes(15)).count()).isEqualTo(1);
        assertThat(rejected.countFailuresFromSource(ip, at.minusMinutes(15)).count()).isEqualTo(1);
    }

    @Test
    void moving_onto_a_taken_address_is_refused_not_obeyed() {
        UserRepository users = context.getBean(UserRepository.class);
        Email mover = Email.of("mover@example.com");
        Email occupied = Email.of("occupied@example.com");
        users.save(new User(mover, new HashedPassword("hash-1")));
        users.save(new User(occupied, new HashedPassword("hash-2")));

        // a change token is requested against a FREE address and followed up to a day later; the
        // address can be registered in between, and the answer must be the one save gives
        assertThatThrownBy(() -> users.updateEmail(mover, occupied))
                .isInstanceOf(EmailAlreadyTakenException.class);
        assertThat(users.findBy(occupied).orElseThrow().passwordHash().value())
                .as("the occupant's account must survive somebody else's change")
                .isEqualTo("hash-2");
        assertThat(users.findBy(mover)).as("and the mover stays where they were").isPresent();
    }

    @Test
    void an_over_long_user_agent_still_records_the_failure() {
        RejectedAuthenticationRepository rejected = context.getBean(RejectedAuthenticationRepository.class);
        // the header is the caller's to write, and user_agent is VARCHAR(400): unclamped, Postgres
        // refused the INSERT, the request answered 500 and NO failure was recorded — so a long
        // enough User-Agent bought unlimited guesses at a password
        Source longAgent = new Source(new IpAddress("203.0.113.11"), "A".repeat(1000));
        LockoutSubject subject = new LockoutSubject(longAgent, AttemptedAccount.of(Email.of("long-ua@example.com")));
        LocalDateTime at = LocalDateTime.now();

        rejected.create(new RejectedAuthenticationDetails(subject, at));

        assertThat(rejected.countFailuresOnAccount(subject, at.minusMinutes(15)).count())
                .as("the attempt must be counted; forensic context is truncated, never dropped")
                .isEqualTo(1);
    }

    @Test
    void a_block_is_upserted_found_and_removed() {
        AuthenticationBlockRepository blocks = context.getBean(AuthenticationBlockRepository.class);
        Source ip = Source.of(new IpAddress("203.0.113.11"));
        blocks.create(new AuthenticationBlock(ip, LocalDateTime.now().plusMinutes(5)));
        blocks.create(new AuthenticationBlock(ip, LocalDateTime.now().plusMinutes(10))); // upsert, must not collide

        assertThat(blocks.findBy(ip)).isPresent();

        blocks.removeAllFor(ip);
        assertThat(blocks.findBy(ip)).isEmpty();
    }

    @Test
    void a_session_is_found_by_refresh_token_then_rotated_and_its_family_revoked() {
        AuthorizationDataRepository sessions = context.getBean(AuthorizationDataRepository.class);
        SessionFamily family = SessionFamily.start();
        SessionTokens session = SessionTokens.createFor(
                Email.of("jdbc-session@example.com"), SESSION_CONFIG, Clock.systemUTC());

        sessions.create(session, family);

        StoredSession found = sessions.findByRefreshToken(session.refreshToken()).orElseThrow();
        assertThat(found.email().value()).isEqualTo("jdbc-session@example.com");
        assertThat(found.family()).isEqualTo(family);
        assertThat(found.status()).isEqualTo(SessionStatus.ACTIVE);
        assertThat(sessions.findByRefreshToken(RefreshToken.random())).isEmpty();

        sessions.markRotated(session.refreshToken());
        assertThat(sessions.findByRefreshToken(session.refreshToken()))
                .get().extracting(StoredSession::status).isEqualTo(SessionStatus.ROTATED);

        sessions.revokeFamily(family);
        assertThat(sessions.findByRefreshToken(session.refreshToken())).isEmpty();
    }

    @Test
    void an_access_token_authorizes_only_while_its_session_is_active() {
        AuthorizationDataRepository sessions = context.getBean(AuthorizationDataRepository.class);
        SessionTokens session = SessionTokens.createFor(
                Email.of("jdbc-access@example.com"), SESSION_CONFIG, Clock.systemUTC());

        sessions.create(session, SessionFamily.start());

        Optional<AccessGrant> grant = sessions.findByAccessToken(session.accessToken());
        assertThat(grant).isPresent();
        assertThat(grant.get().email().value()).isEqualTo("jdbc-access@example.com");
        assertThat(sessions.findByAccessToken(AccessToken.random())).isEmpty();

        sessions.markRotated(session.refreshToken());
        assertThat(sessions.findByAccessToken(session.accessToken())).isEmpty();
    }

    /**
     * The address-keyed tables move with the account. Only the JDBC adapters can prove this: their
     * primary keys are the flattened surrogates {@code email|type} and {@code email|hash}, so a move
     * is a delete plus an insert under a RECOMPUTED id — an UPDATE of the address column alone would
     * leave rows nobody can address (and the in-memory dubles, keyed by the address itself, cannot
     * expose that class of mistake).
     */
    @Test
    void address_keyed_rows_move_with_the_account_under_recomputed_ids() {
        EnrolledFactorRepository factors = context.getBean(EnrolledFactorRepository.class);
        RecoveryCodeRepository codes = context.getBean(RecoveryCodeRepository.class);
        PasswordlessAccountRepository passwordless = context.getBean(PasswordlessAccountRepository.class);
        Email before = Email.of("jdbc-move-old@example.com");
        Email after = Email.of("jdbc-move-new@example.com");

        factors.enrol(new EnrolledFactor(before, FactorType.EMAIL_CODE, "e-mail code", 2, before.value()));
        codes.replaceAll(before, List.of("move-hash-1", "move-hash-2"));
        passwordless.setPasswordless(before, true);

        factors.reassign(before, after);
        codes.reassign(before, after);
        passwordless.reassign(before, after);

        assertThat(factors.findByUser(before)).isEmpty();
        assertThat(factors.findByUser(after)).singleElement().satisfies(factor -> {
            assertThat(factor.type()).isEqualTo(FactorType.EMAIL_CODE);
            assertThat(factor.order()).isEqualTo(2);
            // the code target followed too: secret_material is where the NEXT code is sent
            assertThat(factor.secretMaterial()).isEqualTo(after.value());
        });
        assertThat(codes.unusedCount(before)).isZero();
        assertThat(codes.unusedCount(after)).isEqualTo(2);
        // the id was recomputed, not just the address column: spending by the new key must find the row
        assertThat(codes.consume(after, "move-hash-1")).isTrue();
        assertThat(passwordless.isPasswordless(before)).isFalse();
        assertThat(passwordless.isPasswordless(after)).isTrue();
    }

    /**
     * A pending reset now carries the moment it was requested (migration V20) and can be dropped
     * outright — a link that outlives its account is redeemed against the address's next owner.
     */
    @Test
    void a_pending_reset_carries_its_age_and_can_be_purged() {
        PasswordResetRepository resets = context.getBean(PasswordResetRepository.class);
        Email email = Email.of("jdbc-reset@example.com");
        // the application's clock, not the wall clock: it is UTC, and the TTL check compares against
        // that same clock — reading the local time here would just measure the machine's offset
        LocalDateTime justBefore = LocalDateTime.now(context.getBean(Clock.class)).minusMinutes(1);

        resets.startReset(email, new PasswordResetToken("jdbc-reset-purged"));
        resets.purge(email);
        assertThat(resets.consumeReset(new PasswordResetToken("jdbc-reset-purged"))).isEmpty();

        resets.startReset(email, new PasswordResetToken("jdbc-reset-live"));
        assertThat(resets.consumeReset(new PasswordResetToken("jdbc-reset-live"))).get()
                .satisfies(pending -> {
                    assertThat(pending.email()).isEqualTo(email);
                    assertThat(pending.requestedAt()).isAfter(justBefore);
                });
    }

    /** Both pending-token tables forget an address on request, {@code email_changes} at either end. */
    @Test
    void pending_tokens_are_purged_by_address() {
        EmailChangeRepository changes = context.getBean(EmailChangeRepository.class);
        EmailVerificationRepository verifications = context.getBean(EmailVerificationRepository.class);
        Email leaving = Email.of("jdbc-purge-leaving@example.com");
        Email arriving = Email.of("jdbc-purge-arriving@example.com");

        changes.startChange(new EmailChange(leaving, Email.of("jdbc-purge-x@example.com")),
                new VerificationToken("jdbc-change-as-source"));
        changes.startChange(new EmailChange(Email.of("jdbc-purge-y@example.com"), arriving),
                new VerificationToken("jdbc-change-as-target"));
        verifications.markVerified(leaving);

        changes.purge(leaving);
        changes.purge(arriving);
        verifications.purge(leaving);

        assertThat(changes.confirmChange(new VerificationToken("jdbc-change-as-source"))).isEmpty();
        assertThat(changes.confirmChange(new VerificationToken("jdbc-change-as-target"))).isEmpty();
        assertThat(verifications.isVerified(leaving)).isFalse();
    }

    @Test
    void a_duplicate_email_is_rejected_by_the_unique_constraint() {
        UserRepository users = context.getBean(UserRepository.class);
        Email email = Email.of("jdbc-duplicate@example.com");
        users.save(new User(email, new HashedPassword("hash-a")));

        assertThatThrownBy(() -> users.save(new User(email, new HashedPassword("hash-b"))))
                .isInstanceOf(EmailAlreadyTakenException.class);
    }

    @Test
    void security_settings_rows_reach_the_snapshot_as_text_and_an_absent_row_is_a_vacant_level() throws Exception {
        LiveConfigPort<?> settings = context.getBean(LiveConfigPort.class);
        try (var connection = java.sql.DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var insert = connection.createStatement()) {
            insert.execute("INSERT INTO security_settings (name, value) VALUES"
                    + " ('security.settings.sample', '10'),"
                    + " ('security.settings.broken', 'not-a-number')");
        }

        // rows written behind the API's back reach the snapshot when it is next taken - at a start
        // or after an admin's write; here, as a start would
        context.getBean(SnapshotLiveConfigPort.class).refresh();

        // text in, text out: the ladder's rung parses and refuses, never the table
        assertThat(settings.find("security.settings.sample")).isEqualTo("10");
        assertThat(settings.find("security.settings.broken")).isEqualTo("not-a-number");
        assertThat(settings.find("security.settings.never.set")).isNull();
    }

    @Test
    void the_admin_store_upserts_the_min_length_row_and_the_snapshot_sees_it_at_once() throws Exception {
        var store = context.getBean(SettingsRepository.class);
        LiveConfigPort<?> settings = context.getBean(LiveConfigPort.class);
        SecuritySettingsTable table = context.getBean(SecuritySettingsTable.class);
        try {
            store.save(MinLength.KEY, "10");
            assertThat(table.rows()).containsEntry(MinLength.KEY, "10");
            assertThat(settings.find(MinLength.KEY)).isEqualTo("10");

            // a second decision replaces the row - one key, one row, never a duplicate - and the
            // snapshot is refreshed by the write itself
            store.save(MinLength.KEY, "12");
            assertThat(table.rows()).containsEntry(MinLength.KEY, "12");
            assertThat(settings.find(MinLength.KEY)).isEqualTo("12");
        } finally {
            // the shared container outlives this method and the settings test next door inserts
            // rows by hand - leave the table as found, whatever the run order
            try (var connection = java.sql.DriverManager.getConnection(
                    POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                 var delete = connection.createStatement()) {
                delete.execute("DELETE FROM security_settings WHERE name = '" + MinLength.KEY + "'");
            }
        }
    }
}
