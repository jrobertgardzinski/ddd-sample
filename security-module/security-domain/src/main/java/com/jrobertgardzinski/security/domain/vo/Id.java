package com.jrobertgardzinski.security.domain.vo;

import jakarta.validation.constraints.NotNull;

public record Id(@NotNull Long value) {
}
