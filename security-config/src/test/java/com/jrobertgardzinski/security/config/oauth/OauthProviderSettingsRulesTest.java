package com.jrobertgardzinski.security.config.oauth;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What a deployment may and may not say about a social provider — the type had no test at all, and
 * two of its rules did not exist.
 *
 * <p>Each case below is a deployment mistake that used to be discovered somewhere else: a URL with
 * no scheme, met at the callback as a 500 on the security origin in the middle of somebody's
 * sign-in; a USERINFO knob on an ID_TOKEN provider, an intention this service silently does not
 * honour; a missing userinfo-url, which takes GET /oauth/providers down and with it every social
 * button at once.
 */
@Epic("Security")
@Feature("Security Configuration - OAuth provider")
class OauthProviderSettingsRulesTest {

    @Test
    @DisplayName("a complete ID_TOKEN provider is accepted, and fills in what it can")
    void acceptsAnIdTokenProvider() {
        OauthProviderSettings google = provider(OauthProviderSettings.IdentitySource.ID_TOKEN,
                null, null, false);

        assertEquals("Google", google.label(), "the button's words default to the provider's name");
        assertEquals("openid email", google.scope());
        assertEquals("sub", google.subjectField());
    }

    @Test
    @DisplayName("a URL that is not a URL fails the boot, not the callback")
    void refusesUrlsThatAreNotUrls() {
        assertThrows(IllegalArgumentException.class, () -> new OauthProviderSettings(
                        "google", null, OauthProviderSettings.IdentitySource.ID_TOKEN, "https://idp.example",
                        "idp:8091/authorize", "https://idp.example/token", null, null,
                        "id", "secret", "https://security.example/oauth/callback", null, null, null, null, false),
                "a missing scheme becomes a 500 in the middle of somebody's sign-in weeks later");
        assertThrows(IllegalArgumentException.class, () -> new OauthProviderSettings(
                "google", null, OauthProviderSettings.IdentitySource.ID_TOKEN, "https://idp.example",
                "https://idp.example/authorize", "ftp://idp.example/token", null, null,
                "id", "secret", "https://security.example/oauth/callback", null, null, null, null, false));
    }

    @Test
    @DisplayName("a USERINFO provider needs somewhere to ask, and an ID_TOKEN one must not be given one")
    void theIdentitySourceDecidesWhichKnobsMean() {
        assertThrows(IllegalArgumentException.class, () -> provider(
                        OauthProviderSettings.IdentitySource.USERINFO, null, null, false),
                "without a userinfo-url this provider takes GET /oauth/providers down with it");

        assertDoesNotThrow(() -> provider(OauthProviderSettings.IdentitySource.USERINFO,
                "https://idp.example/userinfo", "https://idp.example/emails", true));

        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class, () -> provider(
                OauthProviderSettings.IdentitySource.ID_TOKEN, "https://idp.example/userinfo", null, false));
        assertTrue(refused.getMessage().contains("ID_TOKEN"), refused.getMessage());
        assertThrows(IllegalArgumentException.class, () -> provider(
                        OauthProviderSettings.IdentitySource.ID_TOKEN, null, null, true),
                "assume-email-verified on an ID_TOKEN provider is an intention nobody honours");
    }

    @Test
    @DisplayName("the six things every provider needs are named one by one when they are missing")
    void refusesAnIncompleteProvider() {
        for (String missing : new String[]{"name", "authorize-url", "token-url", "client-id",
                "client-secret", "redirect-uri"}) {
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                    () -> without(missing), "a provider without a " + missing + " must be refused");
            assertTrue(refused.getMessage().contains(missing),
                    "the operator has to be told WHICH one: " + refused.getMessage());
        }
    }

    private static OauthProviderSettings provider(OauthProviderSettings.IdentitySource source,
                                                  String userinfoUrl, String emailsUrl,
                                                  boolean assumeEmailVerified) {
        return new OauthProviderSettings("google", null, source, "https://idp.example",
                "https://idp.example/authorize", "https://idp.example/token", userinfoUrl, emailsUrl,
                "id", "secret", "https://security.example/oauth/callback", null, null, null, null,
                assumeEmailVerified);
    }

    private static OauthProviderSettings without(String key) {
        return new OauthProviderSettings(
                "name".equals(key) ? null : "google", null, OauthProviderSettings.IdentitySource.ID_TOKEN,
                "https://idp.example",
                "authorize-url".equals(key) ? null : "https://idp.example/authorize",
                "token-url".equals(key) ? null : "https://idp.example/token",
                null, null,
                "client-id".equals(key) ? null : "id",
                "client-secret".equals(key) ? null : "secret",
                "redirect-uri".equals(key) ? null : "https://security.example/oauth/callback",
                null, null, null, null, false);
    }
}
