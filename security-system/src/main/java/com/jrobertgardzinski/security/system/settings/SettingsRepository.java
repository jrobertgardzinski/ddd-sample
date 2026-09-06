package com.jrobertgardzinski.security.system.settings;

/** The write side of the live level, save alone on purpose: the ladder is the one that reads. */
public interface SettingsRepository {
    /** The one row under this key, as text the ladder will parse back. */
    void save(String key, String text);
}
