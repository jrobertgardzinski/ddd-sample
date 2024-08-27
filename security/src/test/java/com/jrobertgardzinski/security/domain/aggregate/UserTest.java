package com.jrobertgardzinski.security.domain.aggregate;

import com.jrobertgardzinski.security.domain.vo.Email;
import com.jrobertgardzinski.security.domain.vo.Id;
import com.jrobertgardzinski.security.domain.vo.Password;
import jakarta.validation.ValidationException;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class UserTest {
    @Test
    void failAll() {
        ValidationException exception =
                assertThrows(
                        ValidationException.class,
                        () -> new User(
                                new Id(null),
                                new Email("ab"),
                                new Password("lengthypassword")));

        System.out.println(exception.getMessage());

        assertAll(
                () -> List.of("Id", "Login", "Password").contains(exception.getMessage())
        );
    }

    @Test
    void success() {
        assertDoesNotThrow(
                () -> new User(
                        new Id(1L),
                        new Email("abc@gmail.com"),
                        new Password("Lengthypassword123!")));
    }
}