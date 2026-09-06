package com.jrobertgardzinski;

import com.jrobertgardzinski.config.Configuration;
import com.jrobertgardzinski.config.ladder.Level;
import com.jrobertgardzinski.config.ladder.Resolution;
import com.jrobertgardzinski.config.source.live.LiveConfigPort;
import com.jrobertgardzinski.config.source.restart.RestartConfigPort;
import com.jrobertgardzinski.password.config.MinLength;
import com.jrobertgardzinski.password.config.RequiresDigit;
import com.jrobertgardzinski.password.config.RequiresLowercase;
import com.jrobertgardzinski.password.config.RequiresUppercase;
import com.jrobertgardzinski.password.config.SpecialChars;
import com.jrobertgardzinski.password.policy.PasswordPolicy;
import io.qameta.allure.Allure;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Story;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Epic("Security")
@Feature("Password policy in force")
@Story("Every rule on the same ladder: a settings row over the deployment's property over the library default, under the record's own key")
class LadderedPasswordPolicyRulesTest {

    /** Two text levels, the way a settings table and a properties file hold them. */
    private final Map<String, String> rows = new HashMap<>();
    private final Map<String, String> properties = new HashMap<>();
    private final LiveConfigPort<String> table = rows::get;
    private final RestartConfigPort<String> deployment = properties::get;

    private LadderedPasswordPolicy policy() {
        return new LadderedPasswordPolicy(new Configuration(table, deployment));
    }

    @Test
    @DisplayName("nothing set anywhere → the library's defaults, every rule from the rebuild level")
    void defaultsWhenEveryLevelIsVacant() {
        assertThat(policy().current()).isEqualTo(PasswordPolicy.withDefaults());
        assertThat(policy().minLengthResolution().source()).isEqualTo(Level.REBUILD.label());
    }

    @Test
    @DisplayName("every rule reads its own key: the deployment's properties become the policy, text parsed on the rung")
    void everyRuleFromItsOwnProperty() {
        properties.put(MinLength.KEY, " 12 ");
        properties.put(SpecialChars.KEY, "#?!");
        properties.put(RequiresUppercase.KEY, "false");
        properties.put(RequiresLowercase.KEY, "FALSE");
        properties.put(RequiresDigit.KEY, "true");
        assertThat(policy().current()).isEqualTo(new PasswordPolicy(new MinLength(12), new SpecialChars("#?!"),
                new RequiresUppercase(false), new RequiresLowercase(false), new RequiresDigit(true)));
    }

    @ParameterizedTest
    @ValueSource(ints = {MinLength.BOUNDARY, 8, 64, 256})
    @DisplayName("a row covers the property: the live level answers the length, the other rules stay the deployment's")
    void liveWinsOnItsOwnKeyAlone(int live) {
        Allure.parameter("live", live);
        properties.put(MinLength.KEY, "12");
        properties.put(RequiresDigit.KEY, "false");
        rows.put(MinLength.KEY, Integer.toString(live));
        PasswordPolicy current = policy().current();
        assertThat(current.minLength()).isEqualTo(new MinLength(live));
        assertThat(current.requiresDigit()).isEqualTo(new RequiresDigit(false));
        assertThat(policy().minLengthResolution().source()).isEqualTo(Level.LIVE.label());
    }

    @Test
    @DisplayName("current() re-reads the live level: a changed row is a changed policy, a deleted row falls through")
    void currentFollowsTheRow() {
        LadderedPasswordPolicy inForce = policy();
        rows.put(MinLength.KEY, "8");
        assertThat(inForce.current().minLength()).isEqualTo(new MinLength(8));
        rows.put(MinLength.KEY, "16");
        assertThat(inForce.current().minLength()).isEqualTo(new MinLength(16));
        rows.remove(MinLength.KEY);
        assertThat(inForce.current().minLength()).isEqualTo(MinLength.DEFAULT);
    }

    @ParameterizedTest
    @ValueSource(ints = {MinLength.BOUNDARY - 1, 3, 0, -10})
    @DisplayName("a row below the floor is refused per resolution, reported with what it held, and the ladder falls through")
    void illegalRowFallsThrough(int held) {
        Allure.parameter("row", held);
        rows.put(MinLength.KEY, Integer.toString(held));
        Resolution<MinLength> resolution = policy().minLengthResolution();
        assertThat(resolution.value()).isEqualTo(MinLength.DEFAULT);
        assertThat(resolution.source()).isEqualTo(Level.REBUILD.label());
        assertThat(resolution.rejected()).singleElement().satisfies(rejected -> {
            assertThat(rejected.source()).isEqualTo(Level.LIVE.label());
            assertThat(rejected.value()).isEqualTo(held);
        });
    }

    @Test
    @DisplayName("a row that is not a number is refused the same way, holding its text")
    void unparseableRowFallsThrough() {
        rows.put(MinLength.KEY, "ten");
        rows.put(RequiresDigit.KEY, "yes");
        assertThat(policy().current()).isEqualTo(PasswordPolicy.withDefaults());
        assertThat(policy().minLengthResolution().rejected()).singleElement()
                .satisfies(rejected -> assertThat(rejected.value()).isEqualTo("ten"));
    }

    @ParameterizedTest
    @ValueSource(ints = {MinLength.BOUNDARY - 1, 3, 0, -10})
    @DisplayName("a property below the floor refuses to build the policy at all, naming the key and the level")
    void illegalPropertyRefusesThePolicy(int property) {
        Allure.parameter("property", property);
        properties.put(MinLength.KEY, Integer.toString(property));
        assertThatThrownBy(this::policy)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(MinLength.KEY)
                .hasMessageContaining(Level.RESTART.label());
    }

    @Test
    @DisplayName("a property that is not its type refuses to build the policy: a flag that is not true/false, a length that is not a number")
    void propertyOfTheWrongTypeRefusesThePolicy() {
        properties.put(RequiresUppercase.KEY, "yes");
        assertThatThrownBy(this::policy).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(RequiresUppercase.KEY).hasMessageContaining("yes");
        properties.clear();
        properties.put(MinLength.KEY, "twelve");
        assertThatThrownBy(this::policy).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(MinLength.KEY).hasMessageContaining("twelve");
    }
}
