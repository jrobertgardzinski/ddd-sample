package com.jrobertgardzinski.persistence;

import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;

import java.time.LocalDateTime;

/**
 * An offboarding outcome this service has already acted on, remembered by the id offboarding
 * derived for it. See {@code V18__processed_offboarding_outcomes.sql} for why the e-mail was not
 * enough to correlate on (V10 is the federated-identities table — this pointer named the wrong
 * migration).
 */
@MappedEntity("processed_offboarding_outcomes")
record ProcessedOutcomeEntity(@Id String id, String outcomeType, LocalDateTime processedAt) {
}
