package com.jrobertgardzinski.security.application.stub;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.Email;

import java.util.Optional;
import java.util.Set;

public class StubUserRepository implements UserRepository {
    private final Set<User> users;

    public StubUserRepository(Set<User> users) {
        this.users = users;
    }

    @Override
    public boolean existsBy(Email email) {
        return users.stream().anyMatch(e -> e.email().equals(email));
    }

    @Override
    public Optional<User> findBy(Email email) {
        return users.stream().filter(e -> e.email().equals(email)).findAny();
    }

    @Override
    public User save(User user) throws Exception {
        users.add(user);
        return user;
    }
}
