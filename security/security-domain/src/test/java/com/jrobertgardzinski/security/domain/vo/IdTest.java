package com.jrobertgardzinski.security.domain.vo;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class IdTest {

    @Test
    void test() {
        assertThrows(NullPointerException.class, () -> new Id(null));
    }
}