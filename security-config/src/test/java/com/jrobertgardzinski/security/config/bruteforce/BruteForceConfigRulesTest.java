package com.jrobertgardzinski.security.config.bruteforce;

import com.jrobertgardzinski.security.config.bruteforce.vo.FailureWindowMinutes;
import com.jrobertgardzinski.security.config.bruteforce.vo.MaxBlockMinutes;
import com.jrobertgardzinski.security.config.bruteforce.vo.MaxFailures;
import com.jrobertgardzinski.security.config.bruteforce.vo.MaxFailuresPerSource;
import com.jrobertgardzinski.security.config.bruteforce.vo.MinBlockMinutes;
import io.qameta.allure.Allure;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import net.jqwik.api.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Epic("Security")
@Feature("Security Configuration - BruteForceConfig")
class BruteForceConfigRulesTest {

    @Example
    @Label("Default")
    void acceptsDefaultValues() {
        BruteForceConfig config = BruteForceConfig.builder().build();
        Allure.parameter("default config", config);
        assertThat(config.failureWindowMinutes()).isEqualTo(FailureWindowMinutes.DEFAULT);
        assertThat(config.maxFailures()).isEqualTo(MaxFailures.DEFAULT);
        assertThat(config.minBlockMinutes()).isEqualTo(MinBlockMinutes.DEFAULT);
        assertThat(config.maxBlockMinutes()).isEqualTo(MaxBlockMinutes.DEFAULT);
    }

    @Example
    @Label("A block window that ends before it starts is refused")
    void refusesMaxBlockBelowMinBlock() {
        assertThrows(IllegalArgumentException.class, () -> BruteForceConfig.builder()
                .minBlockMinutes(10)
                .maxBlockMinutes(3)
                .build());
    }

    @Example
    @Label("A ceiling below the per-account limit is refused: the tighter number would be unreachable")
    void refusesCeilingBelowThePerAccountLimit() {
        // the address would be blocked whole before any single account ever reached its own limit,
        // so the per-account number — the one that models guessing a password — would never decide
        // anything. Both values are legal on their own, which is why the pair has to be judged.
        assertThrows(IllegalArgumentException.class, () -> BruteForceConfig.builder()
                .maxFailures(20)
                .maxFailuresPerSource(5)
                .build());
    }

    @Example
    @Label("A ceiling equal to the per-account limit is legal: the tight number still decides first")
    void acceptsCeilingEqualToThePerAccountLimit() {
        BruteForceConfig config = BruteForceConfig.builder()
                .maxFailures(5)
                .maxFailuresPerSource(5)
                .build();
        assertThat(config.maxFailuresPerSource()).isEqualTo(new MaxFailuresPerSource(5));
    }

    @ParameterizedTest
    @MethodSource("ceilingsOutsideTheRange")
    @DisplayName("the per-source ceiling keeps to its own range")
    void refusesCeilingsOutsideTheRange(int value) {
        // 5 is the floor because an address is not a person — behind one there may be an office or
        // a CI runner — and 500 the ceiling of the ceiling
        assertThrows(IllegalArgumentException.class, () -> new MaxFailuresPerSource(value));
    }

    static Stream<Arguments> ceilingsOutsideTheRange() {
        return Stream.of(Arguments.of(MaxFailuresPerSource.MIN - 1), Arguments.of(MaxFailuresPerSource.MAX + 1),
                Arguments.of(0), Arguments.of(-1));
    }
}
