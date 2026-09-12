package com.jrobertgardzinski;

import com.jrobertgardzinski.security.system.mfa.StepUpStore;
import io.micronaut.scheduling.annotation.Scheduled;
import jakarta.inject.Singleton;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory {@link StepUpStore}, keyed by a random one-shot ticket — the sign-in store's twin. */
@Singleton
final class InMemoryStepUpStore implements StepUpStore {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<String, StepUpPending> byTicket = new ConcurrentHashMap<>();
    private final Clock clock;

    InMemoryStepUpStore(Clock clock) {
        this.clock = clock;
    }

    @Override
    public String open(StepUpPending pending) {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String ticket = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        byTicket.put(ticket, pending);
        return ticket;
    }

    @Override
    public Optional<StepUpPending> find(String ticket) {
        return Optional.ofNullable(byTicket.get(ticket));
    }

    @Override
    public void replace(String ticket, StepUpPending pending) {
        byTicket.put(ticket, pending);
    }

    @Override
    public java.util.Optional<StepUpPending> update(String ticket,
                                                    java.util.function.UnaryOperator<StepUpPending> change) {
        // atomic per ticket, like the sign-in store: two proofs in flight spend two attempts
        return java.util.Optional.ofNullable(
                byTicket.computeIfPresent(ticket, (key, pending) -> change.apply(pending)));
    }

    @Override
    public void close(String ticket) {
        byTicket.remove(ticket);
    }

    /**
     * Drops tickets whose factor chain has aged past its TTL. Without this a step-up abandoned after
     * the password step (never completing the factor) lingered until the process restarted (poz. 17).
     */
    @Scheduled(fixedDelay = "1m")
    void evictExpired() {
        byTicket.values().removeIf(pending -> pending.chain().isExpired(clock));
    }
}
