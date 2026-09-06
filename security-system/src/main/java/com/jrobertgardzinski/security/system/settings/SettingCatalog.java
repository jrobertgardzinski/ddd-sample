package com.jrobertgardzinski.security.system.settings;

import com.jrobertgardzinski.config.LiveKey;

import java.util.Optional;

/**
 * The rules the running system may be told about: every key declared live, each with the gate its
 * text must pass. A key nobody declared is one nobody reads, so it is not here and cannot be set.
 */
public interface SettingCatalog {
    Optional<LiveKey> find(String key);
}
