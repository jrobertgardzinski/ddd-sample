package com.jrobertgardzinski.security.domain.vo;

/**
 * How many failed sign-ins were counted inside the window — on whichever scale the caller asked
 * about.
 *
 * <p>Since V23 there are two: per {@link LockoutSubject} (this address against THIS account — the
 * shape of guessing one password) and per {@link Source} alone (this address against anything at
 * all — the shape of spraying). This type is the answer to either question; which one was asked is
 * the repository method's business. The javadoc said "for a given IpAddress" and named only the
 * second, which is the one that does NOT decide a lockout on its own.
 */
public record FailuresCount(int count) {
    public boolean hasReachedTheLimit(int limit) {
        return count >= limit;
    }
}
