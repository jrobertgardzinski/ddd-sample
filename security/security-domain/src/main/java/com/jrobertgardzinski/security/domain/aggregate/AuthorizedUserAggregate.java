package com.jrobertgardzinski.security.domain.aggregate;

import com.jrobertgardzinski.security.domain.entity.UserDetails;

public record AuthorizedUserAggregate(
        UserDetails userDetails
) {}