package com.jrobertgardzinski.security.domain.entity;

import com.jrobertgardzinski.security.domain.vo.Email;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Calendar;

@RequiredArgsConstructor
public class AuthenticationBlock {
    @Getter
    private final Email email;
    @Getter
    private final Calendar expiryDate;
}
