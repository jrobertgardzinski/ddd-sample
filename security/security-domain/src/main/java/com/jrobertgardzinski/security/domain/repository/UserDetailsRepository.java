package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.UserDetails;
import com.jrobertgardzinski.security.domain.vo.Email;

public interface UserDetailsRepository {
    boolean doesExist(Email email);
    UserDetails create(UserDetails userDetails);
    UserDetails findBy(Email email);
}
