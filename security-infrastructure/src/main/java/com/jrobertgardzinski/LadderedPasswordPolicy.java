package com.jrobertgardzinski;

import com.jrobertgardzinski.config.ConfigValue;
import com.jrobertgardzinski.config.Configuration;
import com.jrobertgardzinski.config.ladder.ConfigLadder;
import com.jrobertgardzinski.config.ladder.Resolution;
import com.jrobertgardzinski.password.config.MinLength;
import com.jrobertgardzinski.password.config.RequiresDigit;
import com.jrobertgardzinski.password.config.RequiresLowercase;
import com.jrobertgardzinski.password.config.RequiresUppercase;
import com.jrobertgardzinski.password.config.SpecialChars;
import com.jrobertgardzinski.password.policy.PasswordPolicy;
import com.jrobertgardzinski.password.policy.PasswordPolicyInForce;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The password policy in force: every rule on the same ladder - a {@code security_settings} row
 * (live) over the deployment's property (restart) over the library default (rebuild), declared
 * from the rule the library ships alone. A property that is not its type or is below a rule's
 * floor refuses the policy where it is built, at startup, and never on a password; a row like
 * that is refused per resolution and the ladder falls through. The live level is one snapshot of
 * the table, so asking five ladders costs one read.
 */
public final class LadderedPasswordPolicy implements PasswordPolicyInForce {

    private final ConfigLadder<MinLength> minLength;
    private final ConfigLadder<SpecialChars> specialChars;
    private final ConfigLadder<RequiresUppercase> requiresUppercase;
    private final ConfigLadder<RequiresLowercase> requiresLowercase;
    private final ConfigLadder<RequiresDigit> requiresDigit;

    public LadderedPasswordPolicy(Configuration configuration) {
        minLength = configuration.liveOver(MinLength.DEFAULT);
        specialChars = configuration.liveOver(SpecialChars.DEFAULT);
        requiresUppercase = configuration.liveOver(RequiresUppercase.DEFAULT);
        requiresLowercase = configuration.liveOver(RequiresLowercase.DEFAULT);
        requiresDigit = configuration.liveOver(RequiresDigit.DEFAULT);
    }

    @Override
    public PasswordPolicy current() {
        return new PasswordPolicy(minLength.resolve(), specialChars.resolve(),
                requiresUppercase.resolve(), requiresLowercase.resolve(), requiresDigit.resolve());
    }

    /**
     * Every rule in force with its provenance, under the rule's key: which level answered and
     * what was refused on the way. In the policy's own order.
     */
    public Map<String, Resolution<? extends ConfigValue<?>>> inForce() {
        Map<String, Resolution<? extends ConfigValue<?>>> inForce = new LinkedHashMap<>();
        for (ConfigLadder<? extends ConfigValue<?>> rule : List.of(minLength, specialChars, requiresUppercase, requiresLowercase, requiresDigit)) {
            inForce.put(rule.key(), rule.resolution());
        }
        return inForce;
    }
}
