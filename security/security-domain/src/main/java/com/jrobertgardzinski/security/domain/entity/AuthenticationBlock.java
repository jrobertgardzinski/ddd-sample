package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.AuthenticationBlockDetails;
import com.jrobertgardzinski.security.domain.vo.AuthenticationBlockId;

public record AuthenticationBlock(AuthenticationBlockId id, AuthenticationBlockDetails details) {
}
