package com.jrobertgardzinski.security.application.feature;

import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.event.brute.force.protection.Blocked;
import com.jrobertgardzinski.security.domain.event.brute.force.protection.BruteForceProtectionEvent;
import com.jrobertgardzinski.security.domain.event.brute.force.protection.Passed;
import com.jrobertgardzinski.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.vo.FailuresCount;
import com.jrobertgardzinski.security.domain.vo.IpAddress;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;
import java.util.function.Function;

public class BruteForceGuard implements Function<IpAddress, BruteForceProtectionEvent> {

    private final FailedAuthenticationRepository failedAuthenticationRepository;
    private final AuthenticationBlockRepository authenticationBlockRepository;

    public BruteForceGuard(FailedAuthenticationRepository failedAuthenticationRepository, AuthenticationBlockRepository authenticationBlockRepository) {
        this.failedAuthenticationRepository = failedAuthenticationRepository;
        this.authenticationBlockRepository = authenticationBlockRepository;
    }

    @Override
    public BruteForceProtectionEvent apply(IpAddress ipAddress) {
        Optional<AuthenticationBlock> optionalAuthenticationBlock = authenticationBlockRepository.findBy(ipAddress)
                .filter(AuthenticationBlock::isStillActive);
        if (optionalAuthenticationBlock.isPresent()) {
            AuthenticationBlock authenticationBlock = optionalAuthenticationBlock.get();
            return new Blocked(authenticationBlock);
        }
        FailuresCount failuresCount = failedAuthenticationRepository.countFailuresBy(ipAddress);
        if (failuresCount.hasReachedTheLimit()) {
            failedAuthenticationRepository.removeAllFor(ipAddress);
            int minutes = new Random().nextInt(8) + 3;
            LocalDateTime until = LocalDateTime.now().plusMinutes(minutes);
            AuthenticationBlock authenticationBlock = authenticationBlockRepository.create(
                    new AuthenticationBlock(
                            ipAddress,
                            until));
            return new Blocked(authenticationBlock);
        }
        return new Passed();
    }
}
