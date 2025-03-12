package com.jrobertgardzinski.security.domain.aggregate;

import com.jrobertgardzinski.security.domain.vo.AuthorizationToken;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.RefreshToken;

public record AuthorizedUserAggregate(
        Email email,
        RefreshToken refreshToken,
        AuthorizationToken authorizationToken
) {}