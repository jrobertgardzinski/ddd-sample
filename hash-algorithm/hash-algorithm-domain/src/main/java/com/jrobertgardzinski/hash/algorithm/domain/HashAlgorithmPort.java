package com.jrobertgardzinski.hash.algorithm.domain;

import com.jrobertgardzinski.security.domain.vo.PasswordHash;
import com.jrobertgardzinski.security.domain.vo.PlaintextPassword;
import com.jrobertgardzinski.security.domain.vo.Salt;

public interface HashAlgorithmPort {
    PasswordHash hash(PlaintextPassword plaintextPassword, Salt salt);
    boolean verify(PasswordHash passwordHash, PlaintextPassword plaintextPassword);
}