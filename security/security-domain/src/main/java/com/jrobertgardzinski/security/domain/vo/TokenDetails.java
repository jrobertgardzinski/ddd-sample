package com.jrobertgardzinski.security.domain.vo;

public record TokenDetails(RefreshToken refreshToken, AuthorizationToken authorizationToken) {
}
