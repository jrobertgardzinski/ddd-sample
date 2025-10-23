package com.jrobertgardzinski.security.domain.vo;

import java.security.SecureRandom;

public record Salt(byte[] value) {
    public Salt {
        int SIZE_LIMIT = 10;
        if (value.length < SIZE_LIMIT) {
            throw new IllegalArgumentException("Min length is  " + SIZE_LIMIT);
        }
    }

    public static Salt generate() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[16];
        secureRandom.nextBytes(bytes);

        return new Salt(bytes);
    }
}
