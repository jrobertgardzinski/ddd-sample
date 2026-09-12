package com.jrobertgardzinski.security.system.mfa;

import java.util.Optional;
import java.util.function.UnaryOperator;

/**
 * Holds sign-ins in flight, keyed by a one-shot ticket handed to the client after link #1. Short-
 * lived and in memory — a lost entry only means the user starts over from the password. The same
 * shape as the OAuth flow store.
 */
public interface PendingAuthenticationStore {

    /** Store a pending authentication and return the fresh ticket that addresses it. */
    String open(PendingAuthentication pending);

    Optional<PendingAuthentication> find(String ticket);

    void replace(String ticket, PendingAuthentication pending);

    /**
     * Read, change and write back as ONE step, returning what is now stored (empty if the ticket is
     * gone).
     *
     * <p>It exists for the attempt counter, and the counter is the reason it must be one step:
     * spending an attempt was read-modify-write across three calls to this store, so twenty wrong
     * proofs presented at once all read the same "five left", all wrote "four left", and all twenty
     * were verified against a ticket that is supposed to allow five. The cap on guesses at a second
     * factor is the whole protection that a factor adds to a password already known.
     *
     * <p>The default implementation is the old sequence and is NOT atomic; an adapter that can do
     * better overrides it, and the in-memory one — which is the production wiring — does.
     */
    default Optional<PendingAuthentication> update(String ticket, UnaryOperator<PendingAuthentication> change) {
        Optional<PendingAuthentication> current = find(ticket);
        current.map(change).ifPresent(next -> replace(ticket, next));
        return current.map(change);
    }

    void close(String ticket);
}
