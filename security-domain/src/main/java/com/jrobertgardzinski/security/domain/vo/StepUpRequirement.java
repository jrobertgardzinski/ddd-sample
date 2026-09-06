package com.jrobertgardzinski.security.domain.vo;

import java.util.Locale;

/**
 * What a caller must re-prove before a sensitive action: nothing beyond the live session, the
 * enrolled second factors, or the password and then the factors.
 */
public enum StepUpRequirement {
    NONE,
    SECOND_FACTORS,
    FULL_CHAIN;

    /** The text a property or a settings row holds; anything that is not one of the three is refused. */
    public static StepUpRequirement parse(String text) {
        try {
            return valueOf(text.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException unknown) {
            throw new IllegalArgumentException(
                    "step-up requirement must be one of NONE, SECOND_FACTORS, FULL_CHAIN but was '" + text + "'");
        }
    }
}
