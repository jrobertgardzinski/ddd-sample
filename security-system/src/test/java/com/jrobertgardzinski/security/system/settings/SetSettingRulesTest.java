package com.jrobertgardzinski.security.system.settings;

import com.jrobertgardzinski.config.Configuration;
import com.jrobertgardzinski.password.config.MinLength;
import com.jrobertgardzinski.password.config.RequiresDigit;
import io.qameta.allure.Allure;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Story;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Example;
import net.jqwik.api.ForAll;
import net.jqwik.api.Label;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@Epic("Security")
@Feature("Settings in force")
@Story("Set any live rule by its key, through the rule's own gate")
class SetSettingRulesTest {

    /** A repository that remembers every row it was asked to keep. */
    private static final class RecordingRepository implements SettingsRepository {
        final Map<String, String> saved = new LinkedHashMap<>();

        @Override
        public void save(String key, String text) {
            saved.put(key, text);
        }
    }

    /** The catalogue as the composition root builds it: from the live declarations alone. */
    private static SettingCatalog catalogueOf(Configuration configuration) {
        return configuration::liveKey;
    }

    private static Configuration aDeploymentWhereTheLengthAndTheDigitRuleAreLive() {
        Configuration configuration = new Configuration(key -> null, key -> null);
        configuration.liveOver(MinLength.DEFAULT);
        configuration.liveOver(RequiresDigit.DEFAULT);
        return configuration;
    }

    @Property
    @Label("a length at or above the boundary is ACCEPTED and saved under the rule's key as text")
    void accepts(@ForAll("legal") int requested) {
        Allure.parameter("requested", requested);
        RecordingRepository store = new RecordingRepository();
        SetSetting.Result result = new SetSetting(catalogueOf(aDeploymentWhereTheLengthAndTheDigitRuleAreLive()), store)
                .execute(MinLength.KEY, " " + requested + " ");
        assertThat(result.status()).isEqualTo(SetSetting.Status.ACCEPTED);
        assertThat(result.value()).isEqualTo(requested);
        assertThat(result.reason()).isEmpty();
        assertThat(store.saved).containsExactly(Map.entry(MinLength.KEY, Integer.toString(requested)));
    }

    @Provide
    Arbitrary<Integer> legal() {
        return Arbitraries.integers().between(MinLength.BOUNDARY, 1024);
    }

    @Property
    @Label("a length below the boundary is REFUSED in the gate's words and NOTHING is saved")
    void refuses(@ForAll("illegal") int requested) {
        Allure.parameter("requested", requested);
        RecordingRepository store = new RecordingRepository();
        SetSetting.Result result = new SetSetting(catalogueOf(aDeploymentWhereTheLengthAndTheDigitRuleAreLive()), store)
                .execute(MinLength.KEY, Integer.toString(requested));
        assertThat(result.status()).isEqualTo(SetSetting.Status.REFUSED);
        assertThat(result.value()).isNull();
        assertThat(result.reason()).isEqualTo("minLength must be at least " + MinLength.BOUNDARY);
        assertThat(store.saved).isEmpty();
    }

    @Provide
    Arbitrary<Integer> illegal() {
        return Arbitraries.integers().between(Integer.MIN_VALUE, MinLength.BOUNDARY - 1);
    }

    @Example
    @Label("text that is not the rule's type is REFUSED naming the text, and NOTHING is saved")
    void refusesTextThatIsNotTheType() {
        RecordingRepository store = new RecordingRepository();
        SetSetting.Result result = new SetSetting(catalogueOf(aDeploymentWhereTheLengthAndTheDigitRuleAreLive()), store)
                .execute(MinLength.KEY, "ten");
        assertThat(result.status()).isEqualTo(SetSetting.Status.REFUSED);
        assertThat(result.reason()).startsWith("'ten' is not the type this key takes");
        assertThat(store.saved).isEmpty();
    }

    @Example
    @Label("a flag is saved in its canonical text, whatever case it was told in")
    void savesTheCanonicalText() {
        RecordingRepository store = new RecordingRepository();
        SetSetting.Result result = new SetSetting(catalogueOf(aDeploymentWhereTheLengthAndTheDigitRuleAreLive()), store)
                .execute(RequiresDigit.KEY, "FALSE");
        assertThat(result.status()).isEqualTo(SetSetting.Status.ACCEPTED);
        assertThat(result.value()).isEqualTo(false);
        assertThat(store.saved).containsExactly(Map.entry(RequiresDigit.KEY, "false"));
    }

    @Example
    @Label("a key nobody declared live is UNKNOWN and NOTHING is saved")
    void refusesAKeyNobodyDeclared() {
        RecordingRepository store = new RecordingRepository();
        SetSetting.Result result = new SetSetting(catalogueOf(aDeploymentWhereTheLengthAndTheDigitRuleAreLive()), store)
                .execute("security.password.policy.min.lenght", "10");
        assertThat(result.status()).isEqualTo(SetSetting.Status.UNKNOWN_KEY);
        assertThat(result.reason()).contains("security.password.policy.min.lenght");
        assertThat(store.saved).isEmpty();
    }
}
