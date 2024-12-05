package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.Password;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SecurityServiceTest {
    @Mock
    UserRepository userRepository;
    @Mock
    User user;

    SecurityService securityService;

    @BeforeEach
    void init() {
        securityService = new SecurityService(userRepository);
    }

    @Nested
    class Registration {
        @Test
        void positive() {
            when(userRepository.createUser(user))
                    .thenReturn(Optional.of(user));
            assertEquals(SecurityService.RegistrationEvent.PASSED,
                    securityService.registerUser(user));
        }

        @Test
        void negative() {
            when(userRepository.createUser(user))
                    .thenReturn(Optional.empty());
            assertEquals(SecurityService.RegistrationEvent.FAILED,
                    securityService.registerUser(user));
        }
    }

    @Nested
    class Authentication {
        @Nested
        class PlainText {
            @Mock
            Password plainTextPassword;
            @Mock
            Password wrongPassword;

            @BeforeEach
            void init() {
                when(userRepository.findUserByEmail(user.email()))
                        .thenReturn(Optional.of(user));
                when(user.password())
                        .thenReturn(plainTextPassword);
            }

            @Test
            void positive() {
                assertEquals(
                        SecurityService.AuthenticationEvent.PASSED,
                        securityService.authenticateWithPlainPassword(user.email(), plainTextPassword));
            }

            @Test
            void negative() {
                assertEquals(
                        SecurityService.AuthenticationEvent.FAILED,
                        securityService.authenticateWithPlainPassword(user.email(), wrongPassword));
            }
        }
    }
}