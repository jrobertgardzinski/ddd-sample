package com.jrobertgardzinski;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.password.domain.HashedPassword;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.repository.EmailAlreadyTakenException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@code save} means ONE thing, database or no database (poz. 25).
 *
 * <p>The in-memory adapter is not only a test double: it is the production wiring of every
 * deployment without a datasource. It used to {@code put} over whatever sat under the address, so
 * a registration that lost the race to another one took the account instead of being refused —
 * while the same registration against Postgres got {@link EmailAlreadyTakenException}. The cases
 * below are the in-memory twins of
 * {@code JdbcAdaptersTest.a_duplicate_email_is_rejected_by_the_unique_constraint}.
 */
class InMemoryUserRepositoryTest {

    private final InMemoryUserRepository users = new InMemoryUserRepository();

    @Test
    @DisplayName("a taken address is refused, and the account already there is left alone")
    void a_taken_address_is_refused() {
        Email email = Email.of("leaver@example.com");
        users.save(new User(email, new HashedPassword("the-owner-hash")));

        assertThatThrownBy(() -> users.save(new User(email, new HashedPassword("the-intruder-hash"))))
                .isInstanceOf(EmailAlreadyTakenException.class);
        assertThat(users.findBy(email)).get()
                .extracting(user -> user.passwordHash().value())
                .isEqualTo("the-owner-hash");
    }

    @Test
    @DisplayName("an alias of a taken address is taken too — both indexed columns are UNIQUE")
    void an_alias_of_a_taken_address_is_refused() {
        users.save(new User(Email.of("leaver@gmail.com"), new HashedPassword("the-owner-hash")));

        assertThatThrownBy(() -> users.save(
                new User(Email.of("lea.ver+portal@gmail.com"), new HashedPassword("the-intruder-hash"))))
                .isInstanceOf(EmailAlreadyTakenException.class);
    }

    @Test
    @DisplayName("moving onto a taken address is refused here too — the same law, no database")
    void moving_onto_a_taken_address_is_refused() {
        Email mover = Email.of("mover@example.com");
        Email occupied = Email.of("occupied@example.com");
        users.save(new User(mover, new HashedPassword("hash-1")));
        users.save(new User(occupied, new HashedPassword("hash-2")));

        assertThatThrownBy(() -> users.updateEmail(mover, occupied))
                .as("without this the other person's account was simply replaced — and this adapter"
                        + " is the production wiring wherever no datasource is configured")
                .isInstanceOf(EmailAlreadyTakenException.class);
        assertThat(users.findBy(occupied).orElseThrow().passwordHash().value()).isEqualTo("hash-2");
        assertThat(users.findBy(mover)).isPresent();
    }
}
