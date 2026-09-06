package com.jrobertgardzinski.security.domain.vo;

import com.jrobertgardzinski.config.ConfigValue;

import com.jrobertgardzinski.security.domain.vo.token.AbstractTokenValidityInHours;

/** How long a refresh token stays valid, in hours; the deployment's property over the code default. */
public final class RefreshTokenValidityInHours extends AbstractTokenValidityInHours implements ConfigValue<Integer> {

    /** The name this validity goes by on every level of a deployment's configuration ladder. */
    public static final String KEY = "security.session.refresh.token.validity.hours";
    public static final RefreshTokenValidityInHours DEFAULT = new RefreshTokenValidityInHours(24);


    public RefreshTokenValidityInHours(int value) {
        super(value);
    }

    @Override
    public String key() {
        return KEY;
    }

    @Override
    public Integer defaultValue() {
        return DEFAULT.value();
    }

    @Override
    public RefreshTokenValidityInHours holding(Integer value) {
        return new RefreshTokenValidityInHours(value);
    }
}
