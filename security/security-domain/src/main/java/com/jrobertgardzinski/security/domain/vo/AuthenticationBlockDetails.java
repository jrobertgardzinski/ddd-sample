package com.jrobertgardzinski.security.domain.vo;

import java.util.Calendar;

public record AuthenticationBlockDetails(Email email, Calendar expiryDate) {
}
