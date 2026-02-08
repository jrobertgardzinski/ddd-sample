package com.jrobertgardzinski.security.domain.vo;

public record SessionRefreshRequest(Email email, RefreshToken refreshToken) {

}
