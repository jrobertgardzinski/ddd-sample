package com.jrobertgardzinski.security.domain.vo.security.domain.feature;

import com.jrobertgardzinski.security.domain.vo.FailuresCount;
import com.jrobertgardzinski.security.domain.vo.IpAddress;
import com.jrobertgardzinski.security.domain.vo.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.brute.force.protection.ActivateBlockadeEvent;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.brute.force.protection.BlockadeStillActiveEvent;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.brute.force.protection.BruteForceProtectionEvent;
import com.jrobertgardzinski.security.domain.vo.security.domain.event.brute.force.protection.NoBlockadeEvent;
import com.jrobertgardzinski.security.domain.vo.security.domain.repository.AuthenticationBlockRepository;
import com.jrobertgardzinski.security.domain.vo.security.domain.repository.FailedAuthenticationRepository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;
import java.util.function.Function;

public class BruteForceProtection implements Function<IpAddress, BruteForceProtectionEvent> {

    private final FailedAuthenticationRepository failedAuthenticationRepository;
    private final AuthenticationBlockRepository authenticationBlockRepository;

    public BruteForceProtection(FailedAuthenticationRepository failedAuthenticationRepository, AuthenticationBlockRepository authenticationBlockRepository) {
        this.failedAuthenticationRepository = failedAuthenticationRepository;
        this.authenticationBlockRepository = authenticationBlockRepository;
    }

    @Override
    public BruteForceProtectionEvent apply(IpAddress ipAddress) {
        Optional<AuthenticationBlock> authenticationBlock = authenticationBlockRepository.findBy(ipAddress);
        if (authenticationBlock.isPresent() && authenticationBlock.get().isStillActive()) {
            return new BlockadeStillActiveEvent(authenticationBlock.get().expiryDate());
        }
        FailuresCount failuresCount = failedAuthenticationRepository.countFailuresBy(ipAddress);
        if (failuresCount.hasReachedTheLimit()) {
            failedAuthenticationRepository.removeAllFor(ipAddress);
            int minutes = new Random().nextInt(8) + 3;
            authenticationBlockRepository.create(
                    new AuthenticationBlock(
                            ipAddress,
                            LocalDateTime.now().plusMinutes(minutes)));
            return new ActivateBlockadeEvent(minutes);
        }
        return new NoBlockadeEvent();
    }
}
