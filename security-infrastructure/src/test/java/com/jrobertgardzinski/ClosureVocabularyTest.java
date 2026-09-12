package com.jrobertgardzinski;

import com.jrobertgardzinski.closure.ClosureInitiator;
import com.jrobertgardzinski.security.domain.vo.DeletionInitiator;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The boundary between this service's own word for who asked, and the word five services agreed on.
 *
 * <p>{@link DeletionInitiator} is domain: it decides what a closure MEANS here — whether purge
 * conditions may be stated at all. {@link ClosureInitiator} is the wire vocabulary the portal's
 * orchestrator and every participant read. They are deliberately two types, and this test is the
 * only place that says they must spell the same thing: rename either side and the agreement breaks
 * silently, in the direction where a leaver's erasure is carried out under somebody's conditions.
 */
@Epic("Account deletion")
@Feature("The saga's vocabulary")
class ClosureVocabularyTest {

    @Test
    @DisplayName("every word this service can send is a word the agreement knows, and reads back the same")
    void the_two_vocabularies_agree() {
        for (DeletionInitiator initiator : DeletionInitiator.values()) {
            assertEquals(initiator.name(), ClosureInitiator.of(initiator.wire()).wire(),
                    "identity sends '" + initiator.wire() + "'; the participants read it as"
                            + " something else, and nothing else would notice");
        }
        assertEquals(Arrays.stream(DeletionInitiator.values()).map(Enum::name).sorted().toList(),
                Arrays.stream(ClosureInitiator.values()).map(Enum::name).sorted().toList(),
                "one side grew a value the other has never heard of");
    }
}
