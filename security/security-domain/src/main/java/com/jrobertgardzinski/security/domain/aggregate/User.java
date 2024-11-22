package com.jrobertgardzinski.security.domain.aggregate;

import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.Id;
import com.jrobertgardzinski.security.domain.vo.Password;

public record User(
        Id id,
        Email email,
        Password password
) {}