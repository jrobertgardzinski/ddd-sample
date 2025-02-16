package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.FailedAuthentication;
import com.jrobertgardzinski.security.domain.vo.FailedAuthenticationDetails;
import com.jrobertgardzinski.security.domain.vo.FailuresCount;
import com.jrobertgardzinski.security.domain.vo.UserId;

import java.util.Optional;

public interface FailedAuthenticationRepository {
    FailedAuthentication create(FailedAuthenticationDetails value);
    FailuresCount countFailuresBy(UserId userId);
    void removeAllFor(UserId userId);
}
