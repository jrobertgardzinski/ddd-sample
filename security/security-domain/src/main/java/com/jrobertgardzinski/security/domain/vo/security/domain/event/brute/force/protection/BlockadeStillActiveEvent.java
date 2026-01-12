package com.jrobertgardzinski.security.domain.vo.security.domain.event.brute.force.protection;

import java.time.LocalDateTime;

public record BlockadeStillActiveEvent(LocalDateTime expiryDate) implements BruteForceProtectionEvent {
}
