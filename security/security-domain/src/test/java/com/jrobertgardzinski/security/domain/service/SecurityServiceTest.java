package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.event.registration.RegistrationPassedEvent;
import com.jrobertgardzinski.security.domain.event.registration.UserAlreadyExistsEvent;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.repository.TokenRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.UserDetails;
import com.jrobertgardzinski.security.domain.vo.UserId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SecurityServiceTest {
    @Mock
    UserRepository userRepository;
    @Mock
    TokenRepository tokenRepository;
    @Mock
    FailedAuthenticationRepository failedAuthenticationRepository;
    @Mock
    AuthenticationBlockRepository authenticationBlockRepository;
    @Mock
    UserDetails userDetails;

    SecurityService securityService;

    @BeforeEach
    void init() {
        securityService = new SecurityService(userRepository, tokenRepository, failedAuthenticationRepository, authenticationBlockRepository);
    }

    @Nested
    class Registration {
        @Test
        void positive() {
            when(
                    userRepository.createUser(userDetails))
            .thenReturn(
                    Optional.of(new User(new UserId(1L), userDetails)));
            assertTrue(securityService.register(userDetails).getClass()
                    .isAssignableFrom(RegistrationPassedEvent.class));
        }

        @Test
        void negative() {
            when(
                    userRepository.createUser(userDetails))
            .thenReturn(
                    Optional.empty());
            assertTrue(securityService.register(userDetails).getClass()
                    .isAssignableFrom(UserAlreadyExistsEvent.class));
        }
    }
}