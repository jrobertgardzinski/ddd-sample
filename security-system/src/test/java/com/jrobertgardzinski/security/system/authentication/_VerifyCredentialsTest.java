package com.jrobertgardzinski.security.system.authentication;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.password.domain.HashAlgorithmPort;
import com.jrobertgardzinski.password.domain.HashedPassword;
import com.jrobertgardzinski.password.domain.PlaintextPassword;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.event.AuthenticationEvent;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.Credentials;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Story;
import net.jqwik.api.Example;
import net.jqwik.api.Label;
import net.jqwik.api.lifecycle.BeforeTry;
import org.mockito.Mockito;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Epic("Use case")
@Feature("Authentication")
@Story("Verify credentials")
class _VerifyCredentialsTest {

    record Given(Email email, PlaintextPassword password, HashedPassword hash,
                 Credentials credentials, User user) {}
    private static final Given GIVEN = given();
    private static Given given() {
        Email email = Email.of("user@example.com");
        PlaintextPassword password = PlaintextPassword.of("plaintext");
        HashedPassword hash = new HashedPassword("hash");
        return new Given(email, password, hash,
                new Credentials(email, password),
                new User(email, hash));
    }

    private UserRepository userRepository;
    private HashAlgorithmPort hashAlgorithmPort;
    private _VerifyCredentials verifyCredentials;

    @BeforeTry
    void init() {
        userRepository = Mockito.mock(UserRepository.class);
        hashAlgorithmPort = Mockito.mock(HashAlgorithmPort.class);
        verifyCredentials = new _VerifyCredentials(userRepository, hashAlgorithmPort);
    }

    @Example
    @Label("Valid when the user exists and the password hash matches")
    void valid_when_user_found_and_hash_matches() {
        Mockito.when(userRepository.findBy(GIVEN.email)).thenReturn(Optional.of(GIVEN.user));
        Mockito.when(hashAlgorithmPort.verify(GIVEN.hash, GIVEN.password)).thenReturn(true);

        AuthenticationEvent event = verifyCredentials.execute(GIVEN.credentials);

        assertEquals(new AuthenticationEvent.Valid(GIVEN.email), event);
    }

    @Example
    @Label("Invalid when the user exists but the password hash does not match")
    void invalid_when_user_found_but_hash_mismatches() {
        Mockito.when(userRepository.findBy(GIVEN.email)).thenReturn(Optional.of(GIVEN.user));
        Mockito.when(hashAlgorithmPort.verify(GIVEN.hash, GIVEN.password)).thenReturn(false);

        AuthenticationEvent event = verifyCredentials.execute(GIVEN.credentials);

        assertEquals(new AuthenticationEvent.Invalid(GIVEN.email), event);
    }

    @Example
    @Label("Invalid when no user exists — and the password is still hashed, so the clock says nothing")
    void invalid_when_user_not_found() {
        Mockito.when(userRepository.findBy(GIVEN.email)).thenReturn(Optional.empty());

        AuthenticationEvent event = verifyCredentials.execute(GIVEN.credentials);

        assertAll(
                () -> assertEquals(new AuthenticationEvent.Invalid(GIVEN.email), event),
                // this assertion used to be verifyNoInteractions, which PINNED the defect: skipping
                // the hash for an unknown address answers in a millisecond where a known one costs
                // the full Argon2, and that difference enumerates accounts on an endpoint that
                // refuses to enumerate them in words
                () -> Mockito.verify(hashAlgorithmPort)
                        .verify(Mockito.any(), Mockito.eq(GIVEN.password))
        );
    }
}
