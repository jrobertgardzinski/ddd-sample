package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.UserLombok;
import com.jrobertgardzinski.security.domain.vo.Email;

public interface UserLombokRepository {
    boolean doesExist(Email email);
    UserLombok create(UserLombok userLombok);
    UserLombok findBy(Email email);
}
