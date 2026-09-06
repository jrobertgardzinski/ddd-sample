package com.jrobertgardzinski.security.config.mfa;

import com.jrobertgardzinski.security.config.mfa.vo.AdminMinFactors;
import com.jrobertgardzinski.security.config.mfa.vo.ModeratorMinFactors;
import com.jrobertgardzinski.security.config.mfa.vo.UserMinFactors;

import java.util.Set;

/**
 * The fewest factors each role must present, one value object per role. The floor for a caller is
 * the strictest across their roles; a role nobody configured asks for the USER minimum.
 */
public record MfaPolicy(UserMinFactors user, ModeratorMinFactors moderator, AdminMinFactors admin) {

    /** The strictest floor across the caller's roles (an unknown role asks for the USER minimum). */
    public int requiredFactorCount(Set<String> roleNames) {
        return roleNames.stream()
                .mapToInt(this::minFactorsFor)
                .max()
                .orElse(user.value());
    }

    private int minFactorsFor(String role) {
        return switch (role) {
            case "MODERATOR" -> moderator.value();
            case "ADMIN" -> admin.value();
            default -> user.value();
        };
    }

    public static MfaPolicy withDefaults() {
        return new MfaPolicy(UserMinFactors.DEFAULT, ModeratorMinFactors.DEFAULT, AdminMinFactors.DEFAULT);
    }
}
