package com.jrobertgardzinski.security.system.settings;

import com.jrobertgardzinski.config.ConfigValue;
import com.jrobertgardzinski.config.LiveKey;

import java.util.Optional;

/**
 * An ADMIN's decision on any live rule, made while the system runs: the key names the rule, the
 * text is what the rule is told. There is no code per rule here - the catalogue supplies the
 * rule's own parser and gate, the same ones the ladder reads a row with, so a value the rule
 * would refuse on the way in is refused at the door and nothing is written, and a key nobody
 * declared cannot be written at all. What is written is the value in its canonical text, under
 * the rule's own key, the one the ladder reads.
 */
public class SetSetting {

    public enum Status { ACCEPTED, REFUSED, UNKNOWN_KEY }

    /** {@code value} is the rule's value as held, {@code reason} the gate's words on a refusal. */
    public record Result(Status status, String key, Object value, String reason) {
        static Result accepted(String key, Object value) {
            return new Result(Status.ACCEPTED, key, value, "");
        }

        static Result refused(String key, String reason) {
            return new Result(Status.REFUSED, key, null, reason);
        }

        static Result unknownKey(String key) {
            return new Result(Status.UNKNOWN_KEY, key, null, "no live rule goes by '" + key + "'");
        }
    }

    private final SettingCatalog catalogue;
    private final SettingsRepository store;

    public SetSetting(SettingCatalog catalogue, SettingsRepository store) {
        this.catalogue = catalogue;
        this.store = store;
    }

    public Result execute(String key, String text) {
        Optional<LiveKey> live = catalogue.find(key);
        if (live.isEmpty()) {
            return Result.unknownKey(key);
        }
        ConfigValue<?> held;
        try {
            held = live.get().holding(text);
        } catch (IllegalArgumentException refused) {
            return Result.refused(key, refused.getMessage());
        }
        store.save(key, String.valueOf(held.value()));
        return Result.accepted(key, held.value());
    }
}
