package com.jrobertgardzinski.security.domain.aggregate;

import com.jrobertgardzinski.security.domain.vo.Id;
import com.jrobertgardzinski.security.domain.vo.Login;
import com.jrobertgardzinski.security.domain.vo.Password;

public record User(Id id, Login login, Password password) {
}