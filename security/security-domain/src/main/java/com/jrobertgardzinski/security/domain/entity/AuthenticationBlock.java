package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.AuthenticationBlockDetails;
import com.jrobertgardzinski.security.domain.vo.AuthenticationBlockId;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AuthenticationBlock {
    @Getter
    private final AuthenticationBlockDetails details;

    private final AuthenticationBlockId id;
}
