package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.FailedAuthentication;
import com.jrobertgardzinski.security.domain.vo.FailedAuthenticationDetails;
import com.jrobertgardzinski.security.domain.vo.FailuresCount;
import com.jrobertgardzinski.security.domain.vo.IpAddress;

import java.time.LocalDateTime;

public interface FailedAuthenticationRepository {
    FailedAuthentication create(FailedAuthenticationDetails value);
    FailuresCount countFailuresBy(IpAddress ipAddress, LocalDateTime since);
    void removeAllFor(IpAddress ipAddress);
}
