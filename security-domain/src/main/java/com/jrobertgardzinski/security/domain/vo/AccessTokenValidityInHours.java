package com.jrobertgardzinski.security.domain.vo;

import com.jrobertgardzinski.config.ConfigValue;

import com.jrobertgardzinski.security.domain.vo.token.AbstractTokenValidityInHours;

/** How long an access token stays valid, in hours; the deployment's property over the code default. */
public final class AccessTokenValidityInHours extends AbstractTokenValidityInHours implements ConfigValue<Integer> {

    /** The name this validity goes by on every level of a deployment's configuration ladder. */
    public static final String KEY = "security.session.access.token.validity.hours";
    public static final AccessTokenValidityInHours DEFAULT = new AccessTokenValidityInHours(1);


    public AccessTokenValidityInHours(int value) {
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
}
