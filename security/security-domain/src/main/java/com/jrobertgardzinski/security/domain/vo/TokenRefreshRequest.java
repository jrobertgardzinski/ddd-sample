package com.jrobertgardzinski.security.domain.vo;

public record TokenRefreshRequest(Email email, RefreshToken refreshToken) {

}
