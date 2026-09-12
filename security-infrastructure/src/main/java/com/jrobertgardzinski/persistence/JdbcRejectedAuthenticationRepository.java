package com.jrobertgardzinski.persistence;

import com.jrobertgardzinski.security.domain.entity.RejectedAuthentication;
import com.jrobertgardzinski.security.domain.repository.RejectedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.vo.FailuresCount;
import com.jrobertgardzinski.security.domain.vo.LockoutSubject;
import com.jrobertgardzinski.security.domain.vo.Source;
import com.jrobertgardzinski.security.domain.vo.RejectedAuthenticationDetails;
import com.jrobertgardzinski.security.domain.vo.RejectedAuthenticationId;
import io.micronaut.context.annotation.Requires;
import jakarta.inject.Singleton;

import javax.sql.DataSource;
import java.time.LocalDateTime;

/**
 * PostgreSQL-backed {@link RejectedAuthenticationRepository}: the failed-attempt log the brute-force
 * guard counts over a time window, on two scales — per (source, account) and per source.
 *
 * <p>This is the ONLY place that knows the account is stored as a fingerprint rather than as an
 * address ({@link AccountFingerprint} explains why). Everything above speaks in
 * {@link com.jrobertgardzinski.security.domain.vo.AttemptedAccount}; the secret that turns one into
 * the other is infrastructure's business and never climbs out of this layer.
 *
 * <p>It is also the only place that knows how wide the columns are, which is why the User-Agent is
 * clamped HERE rather than bounded in the domain. It is a client-supplied header of any length, and
 * an over-long one used to make PostgreSQL refuse the INSERT (22001): the exception escaped the
 * transaction boundary, the request answered 500 with the SQL error in it, and — the part that
 * mattered — NO failure row was written. The brute-force guard counts those rows and nothing else
 * rate-limits sign-in, so a caller who sent a long enough User-Agent could guess passwords forever
 * without ever tripping the lockout. Forensic context is worth keeping, never worth losing an
 * attempt over: it is stored to the column's width and truncated beyond it.
 */
@Singleton
@Requires(beans = DataSource.class)
final class JdbcRejectedAuthenticationRepository implements RejectedAuthenticationRepository {

    /** {@code user_agent VARCHAR(400)} — V9__rejected_authentication_user_agent.sql. */
    private static final int USER_AGENT_COLUMN_WIDTH = 400;

    private final RejectedAuthenticationJdbcRepository repository;
    private final AccountFingerprint fingerprint;

    JdbcRejectedAuthenticationRepository(RejectedAuthenticationJdbcRepository repository,
                                         AccountFingerprint fingerprint) {
        this.repository = repository;
        this.fingerprint = fingerprint;
    }

    @Override
    public RejectedAuthentication create(RejectedAuthenticationDetails details) {
        RejectedAuthenticationEntity saved = repository.save(
                new RejectedAuthenticationEntity(null, details.source().ipAddress().value(),
                        clamped(details.source().userAgent()), fingerprint.of(details.account()), details.time()));
        return new RejectedAuthentication(details, new RejectedAuthenticationId(saved.id()));
    }

    private static String clamped(String userAgent) {
        return userAgent.length() <= USER_AGENT_COLUMN_WIDTH
                ? userAgent
                : userAgent.substring(0, USER_AGENT_COLUMN_WIDTH);
    }

    @Override
    public FailuresCount countFailuresOnAccount(LockoutSubject subject, LocalDateTime since) {
        // the guard's first question, and therefore the place to serialise it: everything the guard
        // does after this — the ceiling count, the block it may write — happens inside the same
        // request transaction, so one address's attempts can no longer all read "under the limit"
        // at once and be admitted together
        repository.lockSource(subject.source().ipAddress().value());
        return new FailuresCount((int) repository.countByIpAddressAndAccountFingerprintAndOccurredAtAfter(
                subject.source().ipAddress().value(), fingerprint.of(subject.account()), since));
    }

    @Override
    public FailuresCount countFailuresFromSource(Source source, LocalDateTime since) {
        return new FailuresCount(
                (int) repository.countByIpAddressAndOccurredAtAfter(source.ipAddress().value(), since));
    }

    @Override
    public void removeAllFor(LockoutSubject subject) {
        repository.deleteByIpAddressAndAccountFingerprint(
                subject.source().ipAddress().value(), fingerprint.of(subject.account()));
    }
}
