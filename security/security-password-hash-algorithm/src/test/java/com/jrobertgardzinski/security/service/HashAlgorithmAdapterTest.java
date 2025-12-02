package com.jrobertgardzinski.security.service;

import com.jrobertgardzinski.security.domain.vo.PasswordHash;
import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.Salt;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HashAlgorithmAdapterTest {

    HashAlgorithmAdapter adapter = new HashAlgorithmAdapter();
    PasswordHash hash;

    @BeforeEach
    void init() {
        hash = adapter.hash(new PlainTextPassword("StrongPassword1!"), new Salt("salt123456"));;
    }

    @Test
    void negative() {
        assertFalse(adapter.verify(hash, new PlainTextPassword("StrongPassword2!")));
    }

    @Test
    void positive() {
        assertTrue(adapter.verify(hash, new PlainTextPassword("StrongPassword1!")));
    }
}