package com.jrobertgardzinski.security.domain.service;

import com.jrobertgardzinski.security.domain.entity.User;
import com.jrobertgardzinski.security.domain.exception.AuthenticationFailedException;
import com.jrobertgardzinski.security.domain.exception.UserAlreadyExistsException;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.Password;

public class SecurityService {
    private final UserRepository userRepository;

    public SecurityService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public void registerUser(User user) throws UserAlreadyExistsException {
        userRepository.createUser(user);
    }

    public String authenticateWithPlainPassword(Email email, Password password) throws AuthenticationFailedException {
        User user = userRepository.findUserByEmail(email);
        if (user.password().equals(password)) {
            return "ticket";
        }
        else {
            throw new AuthenticationFailedException();
        }
    }
}
