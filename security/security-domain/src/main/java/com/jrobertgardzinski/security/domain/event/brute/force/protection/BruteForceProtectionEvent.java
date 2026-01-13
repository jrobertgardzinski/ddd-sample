package com.jrobertgardzinski.security.domain.event.brute.force.protection;

public sealed interface BruteForceProtectionEvent permits ActivateBlockadeEvent, BlockadeStillActiveEvent, NoBlockadeEvent {
}
