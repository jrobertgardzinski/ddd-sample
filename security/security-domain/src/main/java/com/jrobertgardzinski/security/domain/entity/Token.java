package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.TokenDetails;
import com.jrobertgardzinski.security.domain.vo.TokenId;

public record Token(TokenId id, TokenDetails details) {
}
