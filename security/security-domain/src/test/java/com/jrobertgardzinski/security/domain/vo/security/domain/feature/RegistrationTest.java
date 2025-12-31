package com.jrobertgardzinski.security.domain.vo.security.domain.feature;

import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.UserRegistration;
import com.jrobertgardzinski.security.domain.vo.hash.algorithm.domain.HashAlgorithmPort;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.registration.UserAlreadyExistsEvent;
import com.jrobertgardzinski.security.domain.vo.security.domain.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RegistrationTest {
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
    PlainTextPassword plainTextPassword;
    @Mock
    Email email;

    @Test
    void positive() {
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