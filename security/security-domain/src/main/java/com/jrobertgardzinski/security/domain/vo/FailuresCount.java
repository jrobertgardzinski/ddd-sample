package com.jrobertgardzinski.security.domain.vo;

public record FailuresCount(int count) {
    public static final int LIMIT = 3;

    public boolean hasReachedTheLimit() {
        return count == LIMIT;
    }
}
