package com.jrobertgardzinski.security.domain.aggregate;

import com.jrobertgardzinski.security.domain.vo.AuthorizationToken;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.RefreshToken;

// TODO - that was close! Rename AuthorizationToken to AccessToken and then follow https://stackoverflow.com/a/54378384/11382755
public record AuthorizedUserAggregate(
        Email email,
        RefreshToken refreshToken,
        AuthorizationToken authorizationToken
) {}