package com.jrobertgardzinski.security.application.feature;

import com.jrobertgardzinski.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.vo.FailedAuthenticationDetails;
import com.jrobertgardzinski.security.domain.vo.IpAddress;

import java.time.LocalDateTime;
import java.util.function.Consumer;

public class UpdateBruteForceRecords implements Consumer<IpAddress> {
    private final FailedAuthenticationRepository failedAuthenticationRepository;

    public UpdateBruteForceRecords(FailedAuthenticationRepository failedAuthenticationRepository) {
        this.failedAuthenticationRepository = failedAuthenticationRepository;
    }

    @Override
    public void accept(IpAddress ipAddress) {
        failedAuthenticationRepository.create(
                new FailedAuthenticationDetails(ipAddress, LocalDateTime.now()));
    }
}
