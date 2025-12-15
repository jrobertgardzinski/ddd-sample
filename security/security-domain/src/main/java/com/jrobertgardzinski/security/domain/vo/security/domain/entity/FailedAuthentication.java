package com.jrobertgardzinski.security.domain.vo.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.FailedAuthenticationDetails;
import com.jrobertgardzinski.security.domain.vo.FailedAuthetincationId;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

public record FailedAuthentication(
    FailedAuthenticationDetails details,
    FailedAuthetincationId id) {
}
