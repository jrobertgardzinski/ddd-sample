package com.jrobertgardzinski.security.domain.vo.token;

import java.util.Objects;
import java.util.UUID;

public abstract class AbstractToken {

    private final String value;

    protected AbstractToken(String value) {
        // null, not just empty: a caller who omits the field (or sends a number, which the boundary
        // reads as absent) used to get "Cannot invoke String.isBlank()" — an NPE escaping as a 500
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Token value must not be blank");
        this.value = value;
    }

    public String value() {
        return value;
    }

    protected static String randomValue() {
        return UUID.randomUUID().toString();
    }

    /**
     * Same KIND of token, same value.
     *
     * <p>It used to be any token with the same string, so an {@code AccessToken} equalled a
     * {@code RefreshToken} that happened to carry it — which is a comparison nobody wants to be
     * right about. Nothing keys a collection by these today; the day something does, the type is
     * half of what makes a token that token.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        return o != null && getClass() == o.getClass() && value.equals(((AbstractToken) o).value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(getClass(), value);
    }

    /**
     * The type and nothing else — never the secret.
     *
     * <p>It returned the raw value, which means the first log line, exception message or debugger
     * dump that ever interpolated a token would have carried a live credential into a system with
     * its own retention. There is no such sink today; there was no rule against one either, and
     * this is the rule. Whoever genuinely needs the secret asks for {@link #value()}, which says so.
     */
    @Override
    public String toString() {
        return getClass().getSimpleName() + "(hidden)";
    }
}
