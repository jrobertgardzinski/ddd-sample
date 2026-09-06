package com.jrobertgardzinski.security.config;

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
 * A law over the session validities, which live in security-domain because the domain computes
 * token expirations from them; the twin of the one in shared/password: each token validity honours
 * the {@link ConfigValue} contract the compiler can check, AND the half it cannot - a
 * {@code public static final DEFAULT} of its own type, a {@code KEY} that is what {@code key()}
 * answers, and a default that is what {@code defaultValue()} answers. The sources are read so a
 * new limit cannot forget one in silence.
 */
@Epic("Security")
@Feature("Configuration")
@Story("Each token validity knows its key, its value and the default the code ships")
class SessionValidityConfigValueLawTest {

    private static final Path SOURCES = Path.of("../security-domain/src/main/java/com/jrobertgardzinski/security/domain/vo");

    @Test
    void each_validity_is_a_ConfigValue_with_a_static_DEFAULT_and_KEY_that_agree_with_the_instance() throws Exception {
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
            assertThat(shipped.key()).startsWith("security.session.");
            assertThat(holdingAnswersWithItsOwnType(shipped)).as("%s.holding() answers with a %s", type.getSimpleName(), type.getSimpleName()).isTrue();
            assertThat(keys.add(shipped.key())).as("the key %s is claimed by two types", shipped.key()).isTrue();
        }
    }

    /** {@code holding} is the constructor in disguise: same type back, same gate. */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private static boolean holdingAnswersWithItsOwnType(ConfigValue<?> shipped) {
        ConfigValue held = ((ConfigValue) shipped).holding(shipped.value());
        return held.getClass() == shipped.getClass() && held.equals(shipped);
    }

    private static List<Class<?>> typesInThePackage() throws IOException {
        try (Stream<Path> files = Files.list(SOURCES)) {
            return files.filter(file -> file.toString().endsWith("ValidityInHours.java"))
                    .map(file -> file.getFileName().toString().replace(".java", ""))
                    .sorted()
                    .<Class<?>>map(name -> {
                        try {
                            return Class.forName("com.jrobertgardzinski.security.domain.vo." + name);
                        } catch (ClassNotFoundException e) {
                            throw new IllegalStateException(e);
                        }
                    })
                    .toList();
        }
    }
}
