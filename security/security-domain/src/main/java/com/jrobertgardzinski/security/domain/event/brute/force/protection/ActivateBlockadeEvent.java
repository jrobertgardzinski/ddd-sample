package com.jrobertgardzinski.security.domain.event.brute.force.protection;

public record ActivateBlockadeEvent(int minutes) implements BruteForceProtectionEvent {
}
