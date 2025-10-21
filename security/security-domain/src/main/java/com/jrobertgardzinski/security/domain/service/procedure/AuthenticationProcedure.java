package com.jrobertgardzinski.security.domain.service.procedure;

import com.jrobertgardzinski.security.domain.aggregate.AuthorizedUserAggregate;
import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.entity.AuthorizationData;
import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.*;

import java.time.LocalDateTime;
import java.util.Calendar;
import java.util.Optional;
import java.util.function.Supplier;

// todo Consider hiding in in a different maven package. I don't want it to be visible in a module using it.
public class AuthenticationProcedure {
    private final UserRepository userRepository;
    private final AuthorizationDataRepository authorizationDataRepository;
    private final FailedAuthenticationRepository failedAuthenticationRepository;
    private final AuthenticationBlockRepository authenticationBlockRepository;
    private final AuthenticationRequest authenticationRequest;
    private Email email;
    private Optional<User> optionalUser;
    private IpAddress ipAddress;
    private Optional<AuthenticationBlock> authenticationBlock;
    private User user;
    private Password password;

    public AuthenticationProcedure(UserRepository userRepository, AuthorizationDataRepository authorizationDataRepository, FailedAuthenticationRepository failedAuthenticationRepository, AuthenticationBlockRepository authenticationBlockRepository, AuthenticationRequest authenticationRequest) {
        this.userRepository = userRepository;
        this.authorizationDataRepository = authorizationDataRepository;
        this.failedAuthenticationRepository = failedAuthenticationRepository;
        this.authenticationBlockRepository = authenticationBlockRepository;
        this.authenticationRequest = authenticationRequest;
    }

    private Supplier<IllegalArgumentException> supplyAuthenticationFailureException(IpAddress ipAddress) {
        failedAuthenticationRepository.create(
                new FailedAuthenticationDetails(ipAddress, LocalDateTime.now())
        );
        return () -> new IllegalArgumentException("Authentication failed!");
    }

    public void checkIfThereIsAnyActiveBlockadeForIpAddress() {
        this.ipAddress = authenticationRequest.ipAddress();
        this.authenticationBlock = authenticationBlockRepository.findBy(ipAddress);
        if (authenticationBlock.isPresent() && authenticationBlock.get().isStillActive()) {
            throw new IllegalArgumentException("The authentication block is still active for machines from your IP address. Please, try again later: " + authenticationBlock.get().expiryDate());
        }
    }

    public void checkIfTheUserExists() {
        this.email = authenticationRequest.email();
        this.optionalUser = userRepository.findBy(email);
        if (optionalUser.isEmpty()) {
            throw supplyAuthenticationFailureException(ipAddress).get();
        }
    }

    public boolean hasTheUserEnteredCorrectPassword() {
        this.user = optionalUser.get();
        this.password = authenticationRequest.password();
        return user.password().enteredRight(password);
    }

    public AuthorizedUserAggregate handleAuthentication() {
        failedAuthenticationRepository.removeAllFor(ipAddress);
        authenticationBlockRepository.removeAllFor(ipAddress);
        authorizationDataRepository.findBy(email)
                .ifPresent(e -> authorizationDataRepository.deleteBy(e.email()));
        var authorizationData = authorizationDataRepository.create(
                new AuthorizationData(
                        email,
                        new RefreshToken(Token.random()),
                        new AccessToken(Token.random()),
                        new RefreshTokenExpiration(TokenExpiration.validInHours(48)),
                        new AuthorizationTokenExpiration(TokenExpiration.validInHours(48))
                )
        );
        return new AuthorizedUserAggregate(email, authorizationData.refreshToken(), authorizationData.accessToken());
    }

    public RuntimeException exception() {
        var failuresCount = failedAuthenticationRepository.countFailuresBy(ipAddress);
        if (failuresCount.hasReachedTheLimit()) {
            failedAuthenticationRepository.removeAllFor(ipAddress);
            var newAuthenticationBlock = authenticationBlockRepository.create(
                    new AuthenticationBlock(ipAddress, Calendar.getInstance()));
            throw new IllegalArgumentException("Too many authentication failures! Try again later: " + newAuthenticationBlock.expiryDate());
        }
        else {
            throw supplyAuthenticationFailureException(ipAddress).get();
        }
    }
}
