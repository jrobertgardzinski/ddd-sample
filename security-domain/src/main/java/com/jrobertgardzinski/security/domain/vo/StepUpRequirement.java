package com.jrobertgardzinski.security.domain.vo;

/**
 * What a caller must re-prove before a sensitive action: nothing beyond the live session, the
 * enrolled second factors, or the password and then the factors.
 *
 * <p>There is no {@code parse} here. There was one, with its own error message and its own test,
 * and nothing in main ever called it: the configuration ladder turns text into an enum constant
 * generically ({@code Parse.forType} in the config library), refusing anything that is not one of
 * these names. Two parsers for one rule is one parser too many — and the untested one is the one
 * the deployment does not use.
 */
public enum StepUpRequirement {
    NONE,
    SECOND_FACTORS,
    FULL_CHAIN;
}
