package com.jrobertgardzinski.security.config.mfa;

import com.jrobertgardzinski.security.domain.vo.StepUpAction;
import com.jrobertgardzinski.security.domain.vo.StepUpRequirement;

import java.util.Collection;
import java.util.EnumMap;
import java.util.Map;

/**
 * The requirement for every action in the catalogue, complete by construction: a policy that
 * leaves an action out is refused, so there is no "action nobody configured" to fall open or
 * closed on - the catalogue is {@link StepUpAction}, and the compiler keeps it whole.
 */
public record StepUpPolicy(Map<StepUpAction, StepUpRequirement> byAction) {

    public StepUpPolicy {
        byAction = Map.copyOf(new EnumMap<>(byAction));
        for (StepUpAction action : StepUpAction.values()) {
            if (!byAction.containsKey(action)) {
                throw new IllegalArgumentException("step-up policy leaves '" + action.wire() + "' without a requirement");
            }
        }
    }

    public static StepUpPolicy of(Collection<StepUpFor> requirements) {
        Map<StepUpAction, StepUpRequirement> byAction = new EnumMap<>(StepUpAction.class);
        for (StepUpFor each : requirements) {
            byAction.put(each.action(), each.requirement());
        }
        return new StepUpPolicy(byAction);
    }

    public StepUpRequirement requirementFor(StepUpAction action) {
        return byAction.get(action);
    }

    /** Every action at the requirement the code ships. */
    public static StepUpPolicy withDefaults() {
        Map<StepUpAction, StepUpRequirement> byAction = new EnumMap<>(StepUpAction.class);
        for (StepUpAction action : StepUpAction.values()) {
            byAction.put(action, action.defaultRequirement());
        }
        return new StepUpPolicy(byAction);
    }
}
