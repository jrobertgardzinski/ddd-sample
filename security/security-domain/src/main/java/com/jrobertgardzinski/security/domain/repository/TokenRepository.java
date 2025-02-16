package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.Token;
import com.jrobertgardzinski.security.domain.vo.UserId;

public interface TokenRepository {
    Token createAuthorizationToken(UserId userId);
}
