package com.jrobertgardzinski;

import java.util.Map;

/**
 * One shape for every refusal this service sends: {@code {"status": "A_CODE"}}.
 *
 * <p>There were three. Some endpoints answered {@code {"status": ...}}, some {@code {"error": ...}},
 * and some sent a bare status line with no body at all — so a client had to know, per endpoint,
 * which of the three to read, and a new endpoint could invent a fourth without anything noticing.
 * The UI ended up asking for both keys in the same branch, which is the shape of a contract nobody
 * states.
 *
 * <p>{@code error} is kept BESIDE {@code status} wherever it was already sent: that is additive
 * within envelope version 1 (workspace ADR 0004), so a consumer written against the old key keeps
 * working while everything new reads one key. A refusal that had no body gains one, which is
 * additive in the same sense — nobody can be broken by a body they did not read.
 */
final class Refusal {

    private Refusal() {
    }

    /** The canonical shape. */
    static Map<String, Object> of(String code) {
        return Map.of("status", code);
    }

    /** The canonical shape plus the key this endpoint has always sent, for the clients that read it. */
    static Map<String, Object> alsoAsError(String code) {
        return Map.of("status", code, "error", code);
    }
}
