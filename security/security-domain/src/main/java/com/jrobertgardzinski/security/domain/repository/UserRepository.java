package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.UserEntity;
import com.jrobertgardzinski.security.domain.vo.User;
import com.jrobertgardzinski.security.domain.vo.Email;

public interface UserRepository {
    default boolean existsBy(Email email) {
        return existsByEmail(email.value());
    }
    boolean existsByEmail(String email);

    default User findBy(Email email) {
        return new User(findByEmail(email.value()));
    }
    UserEntity findByEmail(String email);

    default UserEntity save(User user) {
        UserEntity entity = new UserEntity(user);
        return save(entity);
    }
    UserEntity save(UserEntity userEntity);
}
