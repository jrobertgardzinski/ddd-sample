package com.jrobertgardzinski.security.domain.vo;

import java.util.Calendar;

public record FailedAuthenticationDetails(IpAddress ipAddress, Calendar time) {
}
