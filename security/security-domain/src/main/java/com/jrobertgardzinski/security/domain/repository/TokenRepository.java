package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.AuthorizationData;
import com.jrobertgardzinski.security.domain.vo.Email;

public interface TokenRepository {
    // todo add expiration dates
    AuthorizationData createFor(Email email);
}
