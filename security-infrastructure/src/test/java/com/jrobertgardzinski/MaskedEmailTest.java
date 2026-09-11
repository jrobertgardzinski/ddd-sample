package com.jrobertgardzinski;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * The one masking rule (poz. 27, 36): an e-mail address must not reach a log line whole, and the
 * admin endpoints carry one in a PATH SEGMENT — which the access line of {@link CorrelationIdFilter}
 * writes for every request.
 */
class MaskedEmailTest {

    @Test
    @DisplayName("an address in an admin path is masked, the route stays readable")
    void masksAnAddressInThePath() {
        assertEquals("/admin/users/vi***@example.com/factors/reset",
                MaskedEmail.maskedPath("/admin/users/victim@example.com/factors/reset"));
        assertEquals("/admin/users/vi***@example.com/roles",
                MaskedEmail.maskedPath("/admin/users/victim@example.com/roles"));
        // closing an account puts the address in the path of an ordinary user's own request too,
        // not only an admin's — every access-log line of a deletion would otherwise carry it
        assertEquals("/account/le***@example.com",
                MaskedEmail.maskedPath("/account/leaver@example.com"));
    }

    @Test
    @DisplayName("a percent-encoded @ is masked too — the path may arrive either way")
    void masksAPercentEncodedAddress() {
        String line = MaskedEmail.maskedPath("/admin/users/victim%40example.com/roles");

        assertFalse(line.contains("victim"), "the local part must not survive: " + line);
        assertEquals("/admin/users/vi***@example.com/roles", line);
    }

    @Test
    @DisplayName("a path without an address is returned untouched")
    void leavesOrdinaryPathsAlone() {
        assertEquals("/account/password", MaskedEmail.maskedPath("/account/password"));
        assertEquals("/", MaskedEmail.maskedPath("/"));
        assertEquals(null, MaskedEmail.maskedPath(null));
    }

    @Test
    @DisplayName("an address with nothing before the @ gives away nothing at all")
    void masksADegenerateAddress() {
        assertEquals("***", MaskedEmail.masked("@example.com"));
        assertEquals("***", MaskedEmail.masked("not-an-address"));
        assertEquals("***", MaskedEmail.masked(null));
    }
}
