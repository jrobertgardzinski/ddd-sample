package com.jrobertgardzinski.security.domain.vo;

import java.util.Calendar;

public record AuthenticationBlockDetails(UserId id, Calendar expiryDate) {
}
