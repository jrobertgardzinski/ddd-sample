package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.FailedAuthenticationDetails;
import com.jrobertgardzinski.security.domain.vo.FailedAuthetincationId;

public record FailedAuthentication(FailedAuthetincationId id, FailedAuthenticationDetails details) {
}
