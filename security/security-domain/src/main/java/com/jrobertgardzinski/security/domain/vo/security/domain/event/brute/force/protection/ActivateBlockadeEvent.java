package com.jrobertgardzinski.security.domain.vo.security.domain.event.brute.force.protection;

public record ActivateBlockadeEvent(int minutes) implements BruteForceProtectionEvent {
}
