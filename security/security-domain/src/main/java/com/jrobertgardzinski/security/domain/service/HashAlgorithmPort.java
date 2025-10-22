package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.vo.PlainTextPassword;
import com.jrobertgardzinski.security.domain.vo.PasswordHash;
import com.jrobertgardzinski.security.domain.vo.Salt;

public interface HashAlgorithmPort {
    PasswordHash hash(PlainTextPassword plainTextPassword, Salt salt);
}
