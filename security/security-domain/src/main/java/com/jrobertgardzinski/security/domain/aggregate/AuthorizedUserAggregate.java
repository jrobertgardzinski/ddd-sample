package com.jrobertgardzinski.security.domain.aggregate;

import com.jrobertgardzinski.security.domain.vo.TokenDetails;
import com.jrobertgardzinski.security.domain.vo.UserDetails;

public record AuthorizedUserAggregate(
        UserDetails userDetails,
        TokenDetails tokenDetails
) {}