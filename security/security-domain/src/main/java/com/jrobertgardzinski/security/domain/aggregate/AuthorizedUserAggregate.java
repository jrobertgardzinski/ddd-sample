package com.jrobertgardzinski.security.domain.aggregate;

import com.jrobertgardzinski.security.domain.entity.User;

public record AuthorizedUserAggregate(
        User user,
        String ticket
) {}