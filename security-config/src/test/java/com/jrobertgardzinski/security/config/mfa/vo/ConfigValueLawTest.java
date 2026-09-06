package com.jrobertgardzinski.security.config.mfa.vo;

import com.jrobertgardzinski.config.ConfigValue;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Story;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A law over this package, the twin of the one in shared/password: every MFA rule honours
 * the {@link ConfigValue} contract the compiler can check, AND the half it cannot - a
 * {@code public static final DEFAULT} of its own type, a {@code KEY} that is what {@code key()}
 * answers, and a default that is what {@code defaultValue()} answers. The sources are read so a
 * new limit cannot forget one in silence.
 */
@Epic("Security")
@Feature("Configuration")
@Story("Every MFA rule knows its key, its value and the default the code ships")
class ConfigValueLawTest {

    private static final Path SOURCES = Path.of("src/main/java/com/jrobertgardzinski/security/config/mfa/vo");

    @Test
    void every_rule_is_a_ConfigValue_with_a_static_DEFAULT_and_KEY_that_agree_with_the_instance() throws Exception {
        List<Class<?>> types = typesInThePackage();
        assertThat(types).isNotEmpty();
        Set<String> keys = new HashSet<>();
        for (Class<?> type : types) {
            assertThat(ConfigValue.class).as("%s must implement ConfigValue", type.getSimpleName()).isAssignableFrom(type);

            Field defaultField = type.getField("DEFAULT");
            assertThat(Modifier.isStatic(defaultField.getModifiers()) && Modifier.isFinal(defaultField.getModifiers()))
                    .as("%s.DEFAULT must be public static final", type.getSimpleName()).isTrue();
            assertThat(defaultField.getType()).as("%s.DEFAULT must be a %s", type.getSimpleName(), type.getSimpleName()).isEqualTo(type);
            ConfigValue<?> shipped = (ConfigValue<?>) defaultField.get(null);
            assertThat(shipped.defaultValue()).as("%s.DEFAULT.defaultValue() is what DEFAULT holds", type.getSimpleName()).isEqualTo(shipped.value());

            Field keyField = type.getField("KEY");
            assertThat(Modifier.isStatic(keyField.getModifiers()) && keyField.getType() == String.class)
                    .as("%s.KEY must be a public static String", type.getSimpleName()).isTrue();
            assertThat(shipped.key()).as("%s.key() answers KEY", type.getSimpleName()).isEqualTo(keyField.get(null));
            assertThat(shipped.key()).startsWith("security.mfa.");
            assertThat(keys.add(shipped.key())).as("the key %s is claimed by two types", shipped.key()).isTrue();
        }
    }

    private static List<Class<?>> typesInThePackage() throws IOException {
        try (Stream<Path> files = Files.list(SOURCES)) {
            return files.filter(file -> file.toString().endsWith(".java"))
                    .map(file -> file.getFileName().toString().replace(".java", ""))
                    .sorted()
                    .<Class<?>>map(name -> {
                        try {
                            return Class.forName("com.jrobertgardzinski.security.config.mfa.vo." + name);
                        } catch (ClassNotFoundException e) {
                            throw new IllegalStateException(e);
                        }
                    })
                    .toList();
        }
    }
}
