package com.jrobertgardzinski.hash.algorithm.domain;

import com.jrobertgardzinski.security.domain.vo.PasswordHash;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.Salt;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class HashAlgorithmPortTest {

    protected abstract HashAlgorithmPort hashAlgorithm();
    PasswordHash hash;

    @BeforeEach
    void init() {
        hash = hashAlgorithm().hash(new PlainTextPassword("StrongPassword1!"), new Salt("salt123456"));;
    }

    @Test
    void negative() {
        assertFalse(hashAlgorithm().verify(hash, new PlainTextPassword("StrongPassword2!")));
    }

    @Test
    void positive() {
        assertTrue(hashAlgorithm().verify(hash, new PlainTextPassword("StrongPassword1!")));
    }
}