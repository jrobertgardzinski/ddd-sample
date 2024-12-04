package com.jrobertgardzinski.security.domain.aggregate;

import com.jrobertgardzinski.security.domain.entity.User;

public record UserAggregate(
        User user,
        String ticket
) {}