package com.jrobertgardzinski.security.domain.vo;

import com.jrobertgardzinski.email.domain.Email;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The one invariant this record exists for: a person asking to be forgotten states no conditions.
 * It is tested HERE, on the type, rather than only through the endpoint that builds it — the point
 * of putting it in the constructor was that no future caller can get it wrong, and a test that
 * only ever goes in through today's controller would not notice if that stopped being true.
 */
class AccountClosureTest {

    private static final Email LEAVER = Email.of("leaver@example.com");

    @Test
    @DisplayName("an owner's closure carries no conditions, however it is built")
    void an_owners_closure_states_nothing() {
        assertTrue(AccountClosure.requestedByOwner(LEAVER).choices().rules().isEmpty());

        // the canonical constructor, handed conditions anyway — a caller that assembles the record
        // itself, a stale object, a mapper. The right to erasure is not a thing to bargain over,
        // so the conditions do not survive the construction
        AccountClosure smuggled = new AccountClosure(LEAVER, DeletionInitiator.SELF,
                new PurgeChoices(Map.of("memes", "KEEP_POPULAR_ANONYMIZED:1")));

        assertTrue(smuggled.choices().rules().isEmpty(),
                "conditions must not survive an owner's own closure: " + smuggled.choices().rules());
    }

    @Test
    @DisplayName("an administrator's closure keeps the rule it was given")
    void an_administrators_closure_keeps_its_rule() {
        AccountClosure ban = AccountClosure.requestedByAdministrator(LEAVER,
                new PurgeChoices(Map.of("memes", "KEEP_POPULAR_ANONYMIZED:100")));

        assertEquals(DeletionInitiator.ADMIN, ban.requestedBy());
        assertEquals(Map.of("memes", "KEEP_POPULAR_ANONYMIZED:100"), ban.choices().rules());
    }
}
