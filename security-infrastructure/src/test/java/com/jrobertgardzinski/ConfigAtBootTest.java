package com.jrobertgardzinski;

import io.micronaut.context.ApplicationContext;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * Configuration that is fixed for the life of the service is read at BOOT, so a typo in it stops
 * the service instead of waiting for the first person it affects.
 *
 * <p>All three of these were built inside factory methods Micronaut creates on demand, so the
 * deployment started happily and the refusal arrived later and elsewhere: a misspelt company domain
 * met the first registration, an address with no {@code @} in the bootstrap admins met the first
 * admin request, and a provider missing a required URL took {@code GET /oauth/providers} down with
 * a 500 — which the UI shows as no social sign-in at all.
 */
@Epic("Wiring")
@Feature("Configuration at boot")
class ConfigAtBootTest {

    @Test
    @DisplayName("a company domain with no dot in it fails the boot, not the first registration")
    void a_misspelt_domain_fails_the_boot() {
        assertThrows(Exception.class, () -> run(Map.of("security.email.company.domains", "acme")));
    }

    @Test
    @DisplayName("an address that is not an address fails the boot, not the first admin request")
    void a_misspelt_bootstrap_admin_fails_the_boot() {
        assertThrows(Exception.class, () -> run(Map.of("security.bootstrap-admins", "not-an-address")));
    }

    @Test
    @DisplayName("a USERINFO provider without a userinfo-url fails the boot, not /oauth/providers")
    void an_incomplete_provider_fails_the_boot() {
        assertThrows(Exception.class, () -> run(Map.of(
                "security.oauth.providers.faces.identity-source", "USERINFO",
                "security.oauth.providers.faces.authorize-url", "http://idp.example/authorize",
                "security.oauth.providers.faces.token-url", "http://idp.example/token",
                "security.oauth.providers.faces.client-id", "id",
                "security.oauth.providers.faces.client-secret", "secret",
                "security.oauth.providers.faces.redirect-uri", "http://security.example/oauth/callback")));
    }

    @Test
    @DisplayName("an MFA floor higher than the factors on offer fails the boot, not every ADMIN")
    void an_unreachable_floor_fails_the_boot() {
        // six factors are asked for and four exist: every ADMIN would be refused at /admin/**
        // for ever — including the one who would have to put the number back
        assertThrows(Exception.class, () -> run(Map.of("security.mfa.min.factors.admin", 6)));
    }

    @Test
    @DisplayName("and a deployment that says nothing about any of them still boots")
    void an_absent_rule_is_a_vacant_level() {
        assertDoesNotThrow(() -> run(Map.of()));
    }

    private static void run(Map<String, Object> properties) {
        try (ApplicationContext context = ApplicationContext.run(properties, "test")) {
            context.getBean(BeanFactory.class);
        }
    }
}
