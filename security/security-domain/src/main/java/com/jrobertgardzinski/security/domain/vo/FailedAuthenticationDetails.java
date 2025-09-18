package com.jrobertgardzinski.security.domain.vo;

import java.time.LocalDateTime;

public record FailedAuthenticationDetails(IpAddress ipAddress, LocalDateTime time) {
}
