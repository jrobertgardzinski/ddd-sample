package com.jrobertgardzinski.security.domain.vo;

import com.jrobertgardzinski.security.domain.vo.validation.Additional;
import jakarta.validation.GroupSequence;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

@GroupSequence({Email.class, Additional.class})
public record Email(
        @NotNull
        @Pattern(regexp = "^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$",
                groups = Additional.class,
                message = "Invalid e-mail format")
        String value
) {
}