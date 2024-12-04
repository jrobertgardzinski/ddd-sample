package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.exception.AuthenticationFailedException;
import com.jrobertgardzinski.security.domain.exception.UserAlreadyExistsException;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.Password;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
        void positive() throws UserAlreadyExistsException {
            when(userRepository.createUser(user))
                    .thenReturn(user);
            assertDoesNotThrow(() -> securityService.registerUser(user));
        }

        @Test
        void negative() throws UserAlreadyExistsException {
            when(userRepository.createUser(user))
                    .thenThrow(UserAlreadyExistsException.class);
            assertThrows(UserAlreadyExistsException.class, () -> securityService.registerUser(user));
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
                        .thenReturn(user);
                when(user.password())
                        .thenReturn(plainTextPassword);
            }

            @Test
            void positive() {
                assertDoesNotThrow(
                        () -> securityService.authenticateWithPlainPassword(user.email(), plainTextPassword));
            }

            @Test
            void negative() {
                assertThrows(
                        AuthenticationFailedException.class,
                        () -> securityService.authenticateWithPlainPassword(user.email(), wrongPassword));
            }
        }
    }
}