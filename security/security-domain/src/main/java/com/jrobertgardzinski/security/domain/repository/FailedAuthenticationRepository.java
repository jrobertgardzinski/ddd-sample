package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.FailedAuthentication;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.FailedAuthenticationDetails;
import com.jrobertgardzinski.security.domain.vo.FailuresCount;

public interface FailedAuthenticationRepository {
    FailedAuthentication create(FailedAuthenticationDetails value);
    FailuresCount countFailuresBy(Email email);
    void removeAllFor(Email email);
}
