package com.jrobertgardzinski;

import com.jrobertgardzinski.security.system.mfa.PendingAuthentication;
import com.jrobertgardzinski.security.system.mfa.PendingAuthenticationStore;
import io.micronaut.scheduling.annotation.Scheduled;
import jakarta.inject.Singleton;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Holds sign-ins in flight in memory, keyed by a random one-shot ticket. Not durable on purpose: a
 * lost ticket (a restart, an eviction) only sends the user back to the password step. A shared
 * store takes over if this service scales out — the same trade-off the OAuth flow store and the
 * mail-dedup set make.
 */
@Singleton
final class InMemoryPendingAuthenticationStore implements PendingAuthenticationStore {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<String, PendingAuthentication> byTicket = new ConcurrentHashMap<>();
    private final Clock clock;

    InMemoryPendingAuthenticationStore(Clock clock) {
        this.clock = clock;
    }

    @Override
    public String open(PendingAuthentication pending) {
        String ticket = randomTicket();
        byTicket.put(ticket, pending);
        return ticket;
    }

    @Override
    public Optional<PendingAuthentication> find(String ticket) {
        return Optional.ofNullable(byTicket.get(ticket));
    }

    @Override
    public void replace(String ticket, PendingAuthentication pending) {
        byTicket.put(ticket, pending);
    }

    @Override
    public Optional<PendingAuthentication> update(String ticket,
                                                  java.util.function.UnaryOperator<PendingAuthentication> change) {
        // ConcurrentHashMap.compute holds the bin's lock across the whole function, so two proofs
        // arriving together spend two attempts rather than the same one twice
        return Optional.ofNullable(byTicket.computeIfPresent(ticket, (key, pending) -> change.apply(pending)));
    }

    @Override
    public void close(String ticket) {
        byTicket.remove(ticket);
    }

    /** Drops sign-ins abandoned after the password step once their chain TTL has passed (poz. 17). */
    @Scheduled(fixedDelay = "1m")
    void evictExpired() {
        byTicket.values().removeIf(pending -> pending.isExpired(clock));
    }

    private static String randomTicket() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
