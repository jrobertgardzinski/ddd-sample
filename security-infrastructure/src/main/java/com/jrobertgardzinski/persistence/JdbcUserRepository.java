package com.jrobertgardzinski.persistence;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.email.domain.NormalizedEmail;
import com.jrobertgardzinski.password.domain.HashedPassword;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.repository.EmailAlreadyTakenException;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.Role;
import io.micronaut.context.annotation.Requires;
import io.micronaut.data.exceptions.DataAccessException;
import jakarta.inject.Singleton;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * PostgreSQL-backed {@link UserRepository}: a thin adapter mapping the {@code users} table rows
 * (see {@link UserEntity}) to and from the domain {@link User}. Active only when a datasource is
 * present; otherwise the in-memory repository serves.
 */
@Singleton
@Requires(beans = DataSource.class)
final class JdbcUserRepository implements UserRepository {

    private final UserJdbcRepository repository;

    JdbcUserRepository(UserJdbcRepository repository) {
        this.repository = repository;
    }

    @Override
    public Optional<User> findBy(Email email) {
        // by the normalized form, because that is the identity the unique index enforces; the
        // spelling somebody typed is not part of who they are
        return repository.findByNormalizedEmail(NormalizedEmail.of(email).value())
                .map(JdbcUserRepository::toDomain);
    }

    @Override
    public boolean existsBy(NormalizedEmail normalizedEmail) {
        return repository.existsByNormalizedEmail(normalizedEmail.value());
    }

    @Override
    public void updatePassword(Email email, HashedPassword passwordHash) {
        repository.updatePassword(email.value(), passwordHash.value());
    }

    @Override
    public void updateEmail(Email currentEmail, Email newEmail) {
        try {
            repository.updateEmail(currentEmail.value(), newEmail.value(), NormalizedEmail.of(newEmail).value());
        } catch (DataAccessException e) {
            if (isUniqueViolation(e)) {
                // the same translation save does: the index is what decides, and what it decided
                // is "somebody else holds this address" — not "the database broke"
                throw new EmailAlreadyTakenException();
            }
            throw e;
        }
    }

    @Override
    public void deleteByEmail(Email email) {
        repository.deleteByEmail(email.value());
    }

    @Override
    public void markPendingDeletion(Email email) {
        repository.setPendingDeletion(email.value(), true);
    }

    @Override
    public void clearPendingDeletion(Email email) {
        repository.setPendingDeletion(email.value(), false);
    }

    @Override
    public boolean isPendingDeletion(Email email) {
        return repository.existsByEmailAndPendingDeletionTrue(email.value());
    }

    @Override
    public User save(User user) {
        try {
            repository.save(new UserEntity(
                    user.id(), user.email().value(), user.normalizedEmail().value(), user.passwordHash().value(),
                    false, encodeRoles(user.roles())));
            return user;
        } catch (DataAccessException e) {
            if (isUniqueViolation(e)) {
                throw new EmailAlreadyTakenException();
            }
            throw e;
        }
    }

    @Override
    public void setRoles(Email email, Set<Role> roles) {
        EnumSet<Role> withUser = roles.isEmpty() ? EnumSet.of(Role.USER) : EnumSet.copyOf(roles);
        withUser.add(Role.USER);
        repository.setRoles(email.value(), encodeRoles(withUser));
    }

    private static String encodeRoles(Set<Role> roles) {
        return roles.stream().map(Enum::name).sorted().collect(Collectors.joining(","));
    }

    private static Set<Role> decodeRoles(String roles) {
        if (roles == null || roles.isBlank()) {
            return Set.of(Role.USER);
        }
        Set<Role> parsed = EnumSet.noneOf(Role.class);
        for (String name : roles.split(",")) {
            try {
                parsed.add(Role.valueOf(name.trim()));
            } catch (IllegalArgumentException unknownRole) {
                // a role dropped from the enum: ignore the stale value rather than fail a login
            }
        }
        parsed.add(Role.USER);
        return parsed;
    }

    /** PostgreSQL SQLSTATE 23505 = unique_violation, here the email / normalized-email constraint. */
    private static boolean isUniqueViolation(Throwable e) {
        for (Throwable cause = e; cause != null; cause = cause.getCause()) {
            if (cause instanceof SQLException sql && "23505".equals(sql.getSQLState())) {
                return true;
            }
        }
        return false;
    }

    private static User toDomain(UserEntity entity) {
        Email email = Email.of(entity.email());
        return new User(entity.id(), email, new HashedPassword(entity.passwordHash()),
                NormalizedEmail.of(email), decodeRoles(entity.roles()));
    }
}
