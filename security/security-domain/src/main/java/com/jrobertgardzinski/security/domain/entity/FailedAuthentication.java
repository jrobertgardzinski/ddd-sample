package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.FailedAuthenticationDetails;
import com.jrobertgardzinski.security.domain.vo.FailedAuthetincationId;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class FailedAuthentication {
    @Getter
    private final FailedAuthenticationDetails details;

    private final FailedAuthetincationId id;
}
