package com.jrobertgardzinski.security.domain.feature;

import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.UserAlreadyExistsEvent;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.service.HashAlgorithmPort;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.PasswordHash;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.UserRegistration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class RegistrationTest {
    @Mock
    UserRepository userRepository;
    @Mock
    HashAlgorithmPort hashAlgorithmPort;

    Registration registration;

    PlainTextPassword plainTextPassword;
    Email email;

    @BeforeEach
    void init() {
        registration = new Registration(userRepository, hashAlgorithmPort);
        plainTextPassword = new PlainTextPassword("StrongPassword1!");
        email = new Email("jan.nowak@wp.pl");
    }

    // todo same as SessionRefresh
    @Mock PasswordHash passwordHash;

    @Test
    void positive() throws Exception {
        when(
                userRepository.existsBy(email))
                .thenReturn(
                        false);

        UserRegistration userRegistration = new UserRegistration(email, plainTextPassword);

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
    }
}