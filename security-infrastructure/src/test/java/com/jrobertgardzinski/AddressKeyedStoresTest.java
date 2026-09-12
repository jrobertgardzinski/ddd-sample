package com.jrobertgardzinski;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.password.domain.HashedPassword;
import com.jrobertgardzinski.security.domain.entity.EnrolledFactor;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.repository.PasswordResetRepository;
import com.jrobertgardzinski.security.domain.vo.EmailChange;
import com.jrobertgardzinski.security.domain.vo.FactorType;
import com.jrobertgardzinski.security.domain.vo.SessionFamily;
import com.jrobertgardzinski.security.domain.entity.SessionTokens;
import com.jrobertgardzinski.security.domain.vo.token.AccessToken;
import com.jrobertgardzinski.security.domain.vo.token.expiration.AuthorizationTokenExpiration;
import com.jrobertgardzinski.security.domain.vo.token.RefreshToken;
import com.jrobertgardzinski.security.domain.vo.token.expiration.RefreshTokenExpiration;
import com.jrobertgardzinski.security.domain.vo.token.PasswordResetToken;
import com.jrobertgardzinski.security.domain.vo.token.VerificationToken;
import com.jrobertgardzinski.security.system.account.ConfirmEmailChange;
import com.jrobertgardzinski.security.system.account.DeleteAccount;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The teeth for the address-keyed family of defects, in the spirit of workspace ADR 0006: ONE generic
 * test that states the law once, so the next table keyed by an e-mail address cannot quietly repeat
 * the same four bugs.
 *
 * <p>Identity here is keyed by the e-mail ADDRESS — and the address is mutable, while not one of the
 * tables has a foreign key, so nothing cascades. Every such store therefore owes the account two
 * operations, and P18 found four stores that owed and did not pay:
 *
 * <ol>
 *   <li><b>The move law.</b> After the account's address changes, NOTHING may be left under the old
 *       address. What belongs to the account moves to the new one (factors, recovery codes, the
 *       passwordless mark, federated links, the user row); what was e-mailed to the old address is
 *       dropped (a pending reset, a pending further change). Leaving MFA behind loses the second
 *       factor without a trace; leaving a reset token behind hands the account of the address's next
 *       owner to whoever holds the old link.</li>
 *   <li><b>The purge law.</b> After the account is deleted, NOTHING may be left under its address —
 *       the address is personal data, and a live token matched by address alone would be redeemed
 *       against the next owner of that address.</li>
 * </ol>
 *
 * <p>A new address-keyed table joins the law by joining {@link #storesOf}; forgetting it there is the
 * one remaining failure mode, which is why the list sits next to nothing else.
 *
 * <p>{@code sessions} joined the registry in the 2026-09-08 review (AUTH-3): they are the one store
 * that CANNOT follow the account, because a session remembers only the address it was minted for.
 * Left alive after a move it keeps authorizing as the old address, and once somebody registers that
 * freed address it resolves to THEIR account. So the move revokes them, exactly as the purge does —
 * the same answer a password change and a password reset already give.
 */
class AddressKeyedStoresTest {

    private static final Email OLD = Email.of("owner@example.com");
    private static final Email NEW = Email.of("moved@example.com");
    private static final Email THIRD = Email.of("third@example.com");
    private static final List<Email> ADDRESSES = List.of(OLD, NEW);

    private static final VerificationToken CHANGE_TOKEN = new VerificationToken("the-change-token");
    private static final VerificationToken OTHER_CHANGE_TOKEN = new VerificationToken("another-change-token");
    private static final PasswordResetToken RESET_TOKEN = new PasswordResetToken("the-reset-token");

    /**
     * One store keyed by the address: how to put a row under an address, which addresses still hold
     * something afterwards, and whether its content belongs to the ACCOUNT (so it must follow a move)
     * or to the MAILBOX (so a move drops it).
     */
    private record Store(String table, boolean followsTheAccount, String droppedBecause,
                         Consumer<Email> seed, Supplier<List<Email>> heldUnder) {

        /** A store that follows the account needs no reason for being dropped — it never is. */
        static Store follows(String table, Consumer<Email> seed, Supplier<List<Email>> heldUnder) {
            return new Store(table, true, "", seed, heldUnder);
        }

        static Store dropped(String table, String droppedBecause,
                             Consumer<Email> seed, Supplier<List<Email>> heldUnder) {
            return new Store(table, false, droppedBecause, seed, heldUnder);
        }
    }

    /** All the adapters and both use cases, freshly wired — one fixture per dynamic test. */
    private static final class Fixture {
        final InMemoryUserRepository users = new InMemoryUserRepository();
        final InMemoryAuthorizationDataRepository sessions =
                new InMemoryAuthorizationDataRepository(Clock.systemUTC());
        final InMemoryEnrolledFactorRepository factors = new InMemoryEnrolledFactorRepository();
        final InMemoryRecoveryCodeRepository codes = new InMemoryRecoveryCodeRepository();
        final InMemoryFederatedIdentityRepository federated = new InMemoryFederatedIdentityRepository();
        final InMemoryPasswordlessAccountRepository passwordless = new InMemoryPasswordlessAccountRepository();
        final InMemoryEmailVerificationRepository verifications = new InMemoryEmailVerificationRepository(Clock.systemUTC());
        final InMemoryPasswordResetRepository resets = new InMemoryPasswordResetRepository(Clock.systemUTC());
        final InMemoryEmailChangeRepository changes = new InMemoryEmailChangeRepository(Clock.systemUTC());

        final ConfirmEmailChange confirmEmailChange = new ConfirmEmailChange(changes, users, verifications,
                federated, factors, codes, passwordless, resets, sessions,
                java.time.Duration.ofMinutes(1440), Clock.systemUTC());
        final DeleteAccount deleteAccount = new DeleteAccount(users, sessions, factors, codes, federated,
                verifications, resets, changes, passwordless);

        Fixture() {
            users.save(new User(OLD, new HashedPassword("hash")));   // the account every store belongs to
        }
    }

    private static List<Store> storesOf(Fixture f) {
        return List.of(
                Store.follows("users",
                        address -> { /* the account row is part of every fixture */ },
                        () -> heldWhere(address -> f.users.findBy(address).isPresent())),
                Store.follows("enrolled_factors",
                        address -> f.factors.enrol(new EnrolledFactor(address, FactorType.EMAIL_CODE,
                                "e-mail code", 2, address.value())),
                        () -> heldWhere(address -> !f.factors.findByUser(address).isEmpty())),
                Store.follows("recovery_codes",
                        address -> f.codes.replaceAll(address, List.of("code-hash")),
                        () -> heldWhere(address -> f.codes.unusedCount(address) > 0)),
                Store.follows("passwordless_accounts",
                        address -> f.passwordless.setPasswordless(address, true),
                        () -> heldWhere(f.passwordless::isPasswordless)),
                Store.follows("federated_identities",
                        address -> f.federated.link("google", "durable-subject", address),
                        () -> f.federated.findUserBy("google", "durable-subject").stream().toList()),
                // the move VERIFIES the new address (its own token was delivered there), so this row
                // is expected under the new address as well — hence "follows"
                Store.follows("email_verifications",
                        f.verifications::markVerified,
                        () -> heldWhere(f.verifications::isVerified)),
                // no find-by-address on these two ports by design (a token store is queried by token),
                // so the probe consumes the seeded token once and reports whose address came back
                Store.dropped("password_resets", "was e-mailed to the old address",
                        address -> f.resets.startReset(address, RESET_TOKEN),
                        () -> f.resets.consumeReset(RESET_TOKEN)
                                .map(PasswordResetRepository.PendingReset::email).stream().toList()),
                Store.dropped("email_changes", "was e-mailed to the old address",
                        address -> f.changes.startChange(new EmailChange(address, THIRD), OTHER_CHANGE_TOKEN),
                        () -> f.changes.confirmChange(OTHER_CHANGE_TOKEN)
                                .map(pending -> pending.change().currentEmail()).stream().toList()),
                // a session carries the address and nothing else, so it cannot be re-pointed: one
                // left alive would keep authorizing as the old address — and as its next owner
                Store.dropped("sessions", "remembers an address that is no longer the account's",
                        address -> f.sessions.create(sessionFor(address), SessionFamily.start()),
                        () -> heldWhere(address -> !f.sessions.listActiveSessions(address).isEmpty())));
    }

    private static SessionTokens sessionFor(Email address) {
        LocalDateTime tomorrow = LocalDateTime.now(Clock.systemUTC()).plusDays(1);
        return new SessionTokens(address, RefreshToken.random(), new AccessToken("access-" + address.value()),
                new RefreshTokenExpiration(tomorrow), new AuthorizationTokenExpiration(tomorrow));
    }

    private static List<Email> heldWhere(Predicate<Email> holdsSomething) {
        return ADDRESSES.stream().filter(holdsSomething).toList();
    }

    @TestFactory
    Stream<DynamicTest> nothing_keyed_by_the_old_address_survives_a_move() {
        return storesOf(new Fixture()).stream().map(Store::table).map(table -> DynamicTest.dynamicTest(
                table, () -> {
                    Fixture f = new Fixture();
                    Store store = storesOf(f).stream()
                            .filter(s -> s.table().equals(table)).findFirst().orElseThrow();
                    store.seed().accept(OLD);
                    f.changes.startChange(new EmailChange(OLD, NEW), CHANGE_TOKEN);

                    f.confirmEmailChange.execute(CHANGE_TOKEN);

                    assertEquals(store.followsTheAccount() ? List.of(NEW) : List.of(),
                            store.heldUnder().get(),
                            store.followsTheAccount()
                                    ? table + " must follow the account to its new address"
                                    : table + " " + store.droppedBecause() + " and must be dropped");
                }));
    }

    @TestFactory
    Stream<DynamicTest> nothing_keyed_by_the_address_survives_the_account() {
        return storesOf(new Fixture()).stream().map(Store::table).map(table -> DynamicTest.dynamicTest(
                table, () -> {
                    Fixture f = new Fixture();
                    Store store = storesOf(f).stream()
                            .filter(s -> s.table().equals(table)).findFirst().orElseThrow();
                    store.seed().accept(OLD);

                    f.deleteAccount.execute(OLD);

                    assertEquals(List.of(), store.heldUnder().get(),
                            table + " outlived the account it belonged to");
                }));
    }

    /** The one case the whole family is about, end to end: an unexpiring reset link after a takeover. */
    @TestFactory
    Stream<DynamicTest> a_reset_pending_when_the_account_closes_cannot_be_redeemed_afterwards() {
        return Stream.of(DynamicTest.dynamicTest("the successor of a freed address keeps their password", () -> {
            Fixture f = new Fixture();
            f.resets.startReset(OLD, RESET_TOKEN);

            f.deleteAccount.execute(OLD);
            f.users.save(new User(OLD, new HashedPassword("the-successor-hash")));   // someone else registers it

            Optional<PasswordResetRepository.PendingReset> redeemed = f.resets.consumeReset(RESET_TOKEN);

            assertEquals(Optional.empty(), redeemed,
                    "the old owner's reset link still resolves to the address — it would set the successor's password");
        }));
    }
}
