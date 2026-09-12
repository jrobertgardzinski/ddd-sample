package com.jrobertgardzinski.persistence;

import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;

/**
 * Row of the {@code security_settings} table — the live level of the ladder, copied whole into a
 * snapshot at startup and again after each admin's write (the TTL this comment used to name was
 * removed in 2026-09-06: a clock is not what makes a decision current, a write is). The name is the
 * very key string the other levels use (application.yml,
 * the hardcoded default); the value is text and the ladder parses it on its rung for its own type. No row is a valid state: the level is vacant
 * and the ladder falls through.
 */
@MappedEntity("security_settings")
record SecuritySettingEntity(
        @Id String name,
        String value,
        java.time.LocalDateTime updatedAt) {
}
