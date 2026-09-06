package com.jrobertgardzinski.security.config.mfa;

import com.jrobertgardzinski.config.ConfigValue;
import com.jrobertgardzinski.security.domain.vo.StepUpAction;
import com.jrobertgardzinski.security.domain.vo.StepUpRequirement;

/**
 * The requirement in force for one action. The action is the catalogue entry that carries the
 * key and the shipped default, so the contract is met by the enum constant, not by statics.
 */
public record StepUpFor(StepUpAction action, StepUpRequirement requirement) implements ConfigValue<StepUpRequirement> {

    @Override
    public String key() {
        return action.key();
    }

    @Override
    public StepUpRequirement value() {
        return requirement;
    }

    @Override
    public StepUpRequirement defaultValue() {
        return action.defaultRequirement();
    }
}
