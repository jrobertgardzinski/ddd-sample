package com.jrobertgardzinski.security.system.authentication;

import com.jrobertgardzinski.security.config.bruteforce.BruteForceConfig;

import java.util.concurrent.ThreadLocalRandom;

/**
 * Production {@link BlockDurationPolicy}: a random duration within the configured
 * {@code [minBlockMinutes, maxBlockMinutes]} range.
 *
 * <p>The randomness is about not handing out a schedule, not about secrecy — and the javadoc used
 * to claim the latter ("block lengths are not predictable"). They are: the 429 that announces a
 * block carries {@code Retry-After}, which states this very number to the second, because a caller
 * who is being asked to wait deserves to know how long. What varies is the length from one block to
 * the next, so a script cannot assume the same pause every time and drift into a rhythm around it.
 */
public final class RandomBlockDurationPolicy implements BlockDurationPolicy {

    private final BruteForceConfig config;

    public RandomBlockDurationPolicy(BruteForceConfig config) {
        this.config = config;
    }

    @Override
    public int blockMinutes() {
        return ThreadLocalRandom.current().nextInt(
                config.minBlockMinutes().value(),
                config.maxBlockMinutes().value() + 1);
    }
}
