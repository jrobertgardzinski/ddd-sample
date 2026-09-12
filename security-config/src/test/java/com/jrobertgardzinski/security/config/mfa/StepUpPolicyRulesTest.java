package com.jrobertgardzinski.security.config.mfa;

import com.jrobertgardzinski.security.domain.vo.StepUpAction;
import com.jrobertgardzinski.security.domain.vo.StepUpRequirement;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Epic("Config")
@Feature("Step-up policy")
class StepUpPolicyRulesTest {

    @Test
    @DisplayName("a typo in a requirement is refused by the ladder's parser, never silently degraded (poz. 22)")
    void rejectsUnknownRequirementValue() {
        // 'FULL_CHAN' is neither NONE, SECOND_FACTORS nor FULL_CHAIN — without the refusal it would
        // read as "a live session is enough" and quietly drop the guard on delete-account.
        //
        // Through the ladder's own parser, which is what a property and a settings row go through;
        // the domain used to carry a second parse() that nothing in main called, and this test was
        // the only thing keeping it alive.
        java.util.function.Function<String, StepUpRequirement> parser =
                com.jrobertgardzinski.config.ladder.Parse.forType(StepUpRequirement.class);
        assertThrows(IllegalArgumentException.class, () -> parser.apply("FULL_CHAN"));
        assertEquals(StepUpRequirement.FULL_CHAIN, parser.apply(" full_chain "));
    }

    @Test
    @DisplayName("every action carries its key and the requirement the code ships, and the defaults are the catalogue's")
    void defaultsAreTheCatalogues() {
        StepUpPolicy policy = StepUpPolicy.withDefaults();
        for (StepUpAction action : StepUpAction.values()) {
            assertEquals(action.defaultRequirement(), policy.requirementFor(action));
            assertEquals("security.step.up." + action.wire().replace('-', '.'), action.key());
            assertEquals(action.defaultRequirement(), new StepUpFor(action, StepUpRequirement.NONE).defaultValue());
        }
        assertEquals(StepUpRequirement.FULL_CHAIN, policy.requirementFor(StepUpAction.DELETE_ACCOUNT));
        assertEquals(StepUpRequirement.SECOND_FACTORS, policy.requirementFor(StepUpAction.ENROL_FACTOR));
    }

    @Test
    @DisplayName("a policy that leaves an action out is refused: there is no action nobody configured (poz. 1)")
    void incompletePolicyIsRefused() {
        Map<StepUpAction, StepUpRequirement> missingOne = new EnumMap<>(StepUpAction.class);
        for (StepUpAction action : StepUpAction.values()) {
            missingOne.put(action, action.defaultRequirement());
        }
        missingOne.remove(StepUpAction.ADMIN_SETTINGS);
        assertThrows(IllegalArgumentException.class, () -> new StepUpPolicy(missingOne));
        assertThrows(IllegalArgumentException.class, () -> StepUpPolicy.of(List.of()));
    }

    @Test
    @DisplayName("a deployment's choice for one action is what the policy answers for it")
    void deploymentsChoiceWins() {
        Map<StepUpAction, StepUpRequirement> byAction = StepUpPolicy.withDefaults().byAction();
        Map<StepUpAction, StepUpRequirement> relaxed = new EnumMap<>(byAction);
        relaxed.put(StepUpAction.ENROL_FACTOR, StepUpRequirement.NONE);
        assertEquals(StepUpRequirement.NONE, new StepUpPolicy(relaxed).requirementFor(StepUpAction.ENROL_FACTOR));
    }
}
