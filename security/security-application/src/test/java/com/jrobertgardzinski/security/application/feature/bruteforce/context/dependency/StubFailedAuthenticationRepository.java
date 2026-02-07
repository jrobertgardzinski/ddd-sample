package com.jrobertgardzinski.security.application.feature.bruteforce.context.dependency;

import com.jrobertgardzinski.security.domain.entity.FailedAuthentication;
import com.jrobertgardzinski.security.domain.repository.FailedAuthenticationRepository;
import com.jrobertgardzinski.security.domain.vo.FailedAuthenticationDetails;
import com.jrobertgardzinski.security.domain.vo.FailedAuthetincationId;
import com.jrobertgardzinski.security.domain.vo.FailuresCount;
import com.jrobertgardzinski.security.domain.vo.IpAddress;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class StubFailedAuthenticationRepository implements FailedAuthenticationRepository {

    private final List<FailedAuthenticationDetails> records = new ArrayList<>();
    private long idSequence = 1;

    @Override
    public FailedAuthentication create(FailedAuthenticationDetails value) {
        records.add(value);
        return new FailedAuthentication(value, new FailedAuthetincationId(idSequence++));
    }

    @Override
    public FailuresCount countFailuresBy(IpAddress ipAddress, LocalDateTime since) {
        int count = (int) records.stream()
                .filter(r -> r.ipAddress().equals(ipAddress))
                .filter(r -> !r.time().isBefore(since))
                .count();
        return new FailuresCount(count);
    }

    @Override
    public void removeAllFor(IpAddress ipAddress) {
        records.removeIf(r -> r.ipAddress().equals(ipAddress));
    }
}
