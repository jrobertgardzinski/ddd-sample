package com.jrobertgardzinski.security.domain.vo;

import java.util.Calendar;

// todo make it an entity
public record AuthenticationBlockDetails(Email email, Calendar expiryDate) {
}
