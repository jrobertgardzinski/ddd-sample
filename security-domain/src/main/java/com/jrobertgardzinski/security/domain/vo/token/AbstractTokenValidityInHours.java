package com.jrobertgardzinski.security.domain.vo.token;

import java.util.Objects;

public abstract class AbstractTokenValidityInHours {

    public static final int MIN = 1;

    private final int value;

    protected AbstractTokenValidityInHours(int value) {
        if (value < MIN) throw new IllegalArgumentException("TokenValidityInHours must be >= " + MIN);
        this.value = value;
    }

    public Integer value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AbstractTokenValidityInHours other)) return false;
        return value == other.value;
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return String.valueOf(value);
    }
}
