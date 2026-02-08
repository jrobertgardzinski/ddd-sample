package com.jrobertgardzinski.security.application.feature;

import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;

@ExtendWith(MockitoExtension.class)
class RegistrationTest {/*
    @Mock
    UserRepository userRepository;
    @Mock
    HashAlgorithmPort hashAlgorithmPort;

    Registration registration;

    @BeforeEach
    void init() {
        registration = new Registration(userRepository, hashAlgorithmPort);
    }

    @Mock
    PlainTextPassword plaintextPassword;
    @Mock
    Email email;

    @Test
    void positive() {
        when(
                userRepository.existsBy(email))
                .thenReturn(
                        false);

        UserRegistration userRegistration = new UserRegistration(email, plaintextPassword);

        assertEquals(new RegistrationPassedEvent(userRegistration.email()),
                registration.apply(userRegistration));
    }

    @Test
    void negative() {
        when(
                userRepository.existsBy(email))
                .thenReturn(
                        true);

        assertEquals(new UserAlreadyExistsEvent(),
                registration.apply(new UserRegistration(email, any())));
    }*/
}