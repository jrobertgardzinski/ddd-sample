package com.jrobertgardzinski.security.domain.vo;

import java.util.Calendar;

public record FailedAuthenticationDetails(UserId userId, Calendar time) {
}
