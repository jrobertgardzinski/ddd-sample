package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.IpAddress;

import java.util.Optional;

public interface AuthenticationBlockRepository {
    AuthenticationBlock create(AuthenticationBlock authenticationBlock);
    void removeAllFor(IpAddress ipAddress);
    Optional<AuthenticationBlock> findBy(IpAddress ipAddress);
}
