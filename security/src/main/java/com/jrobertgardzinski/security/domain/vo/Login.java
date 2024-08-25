package com.jrobertgardzinski.security.domain.vo;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record Login(
        @NotNull
        @NotEmpty
        @Size(min = 3, max = 16,
                message = "'${validatedValue}' must be between {min} and {max} characters long")
        @Pattern(regexp = "[a-zA-Z0-9\\-_]",
                message = "May consist only of small and capital letters, hyphen (-) and underscore (_)")
        String value
) {
}
