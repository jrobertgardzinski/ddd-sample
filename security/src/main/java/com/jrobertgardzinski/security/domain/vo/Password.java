package com.jrobertgardzinski.security.domain.vo;

import com.jrobertgardzinski.security.domain.vo.validation.Additional;
import jakarta.validation.GroupSequence;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

@GroupSequence({Password.class, Additional.class})
public record Password(
        @NotNull
        @Size(min = 12,
                message = "must be at least {min} characters long")
        @Pattern(regexp = ".*[a-z].*",
                groups = Additional.class,
                message = "must contain a small letter")
        @Pattern(regexp = ".*[A-Z].*",
                groups = Additional.class,
                message = "must contain a capital letter")
        @Pattern(regexp = ".*\\d.*",
                groups = Additional.class,
                message = "must contain a digit")
        @Pattern(regexp = ".*[#?!].*",
                groups = Additional.class,
                message = "must contain one of special characters: [#, ?, !]")
        String value
) {
}
