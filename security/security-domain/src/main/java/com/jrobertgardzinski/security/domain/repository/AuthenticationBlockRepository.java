package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.vo.AuthenticationBlockDetails;
import com.jrobertgardzinski.security.domain.vo.UserId;

public interface AuthenticationBlockRepository {
    AuthenticationBlock create(AuthenticationBlockDetails authenticationBlockDetails);
    void removeAllFor(UserId id);
}
