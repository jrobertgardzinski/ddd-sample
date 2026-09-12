package com.jrobertgardzinski.persistence;

import io.micronaut.data.annotation.GeneratedValue;
import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;

import java.time.LocalDateTime;

/**
 * Row of the {@code rejected_authentications} table; id is database-generated. The user agent is
 * observed context kept for forensics only — never part of any key. Since V23 the guard counts on
 * two scales: per (address, account fingerprint) — the shape of guessing one password — and per
 * address alone, the ceiling that notices spraying. It is clamped to the column's width by the
 * adapter, because a header long enough to break the INSERT used to mean no failure was recorded
 * at all.
 */
@MappedEntity("rejected_authentications")
record RejectedAuthenticationEntity(@Id @GeneratedValue Long id, String ipAddress, String userAgent,
                                    String accountFingerprint, LocalDateTime occurredAt) {
}
