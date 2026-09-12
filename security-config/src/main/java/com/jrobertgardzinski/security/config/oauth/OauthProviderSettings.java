package com.jrobertgardzinski.security.config.oauth;

/**
 * One social-login identity provider, as the deployment configures it
 * ({@code security.oauth.providers.<name>.*}). Config, not code — adding a provider to a
 * deployment is adding one of these, same discipline as the brute-force policy or the MFA
 * challenge-code lifecycle. The infrastructure layer binds the properties and dances the
 * OAuth protocol; every knob a deployment may turn lives here.
 *
 * <p>{@code authorizeUrl} is browser-facing (the user's redirect target), while
 * {@code tokenUrl}/{@code userinfoUrl}/{@code emailsUrl} are called server-side — in containers
 * they may resolve through different hosts, which is why they are configured separately.
 *
 * <p>Providers assert identity in one of two ways ({@link IdentitySource}):
 * <ul>
 *   <li>{@code ID_TOKEN} (default) — full OIDC: the token endpoint returns a signed
 *       {@code id_token} whose claims are validated (Google, GitLab, the stub IdP);</li>
 *   <li>{@code USERINFO} — plain OAuth2 (Facebook, GitHub): no id_token, so the access token is
 *       spent on a GET to {@code userinfoUrl} and identity is read from that JSON, through the
 *       {@code subjectField}/{@code emailField}/{@code emailVerifiedField} mapping. Providers
 *       that hide the address behind a second endpoint (GitHub's {@code /user/emails}) configure
 *       {@code emailsUrl}; providers that never state verification (Facebook) may declare
 *       {@code assumeEmailVerified} — a deliberate deployment decision, not a default.</li>
 * </ul>
 */
public record OauthProviderSettings(
        String name,
        String label,
        IdentitySource identitySource,
        String issuer,
        String authorizeUrl,
        String tokenUrl,
        String userinfoUrl,
        String emailsUrl,
        String clientId,
        String clientSecret,
        String redirectUri,
        String scope,
        String subjectField,
        String emailField,
        String emailVerifiedField,
        boolean assumeEmailVerified) {

    /** Where the validated identity comes from once the code is exchanged. */
    public enum IdentitySource { ID_TOKEN, USERINFO }

    public OauthProviderSettings {
        require(name, "name");
        requireUrl(authorizeUrl, "authorize-url", name);
        requireUrl(tokenUrl, "token-url", name);
        require(clientId, "client-id");
        require(clientSecret, "client-secret");
        requireUrl(redirectUri, "redirect-uri", name);
        if (identitySource == null) {
            identitySource = IdentitySource.ID_TOKEN;
        }
        if (identitySource == IdentitySource.USERINFO && isBlank(userinfoUrl)) {
            throw new IllegalArgumentException(
                    "a USERINFO provider needs a userinfo-url (provider '" + name + "')");
        }
        requireUrlIfPresent(userinfoUrl, "userinfo-url", name);
        requireUrlIfPresent(emailsUrl, "emails-url", name);
        // The knobs below only mean something to a provider whose identity comes from USERINFO:
        // an ID_TOKEN provider reads its claims from the signed token, and a deployment that set
        // `emails-url` or `assume-email-verified` on one has expressed an intention this service
        // will silently not honour — which is the kind of thing that is noticed after a support
        // ticket about somebody signing in as the wrong person, not at boot.
        if (identitySource == IdentitySource.ID_TOKEN) {
            if (!isBlank(userinfoUrl) || !isBlank(emailsUrl) || assumeEmailVerified) {
                throw new IllegalArgumentException("provider '" + name + "' is an ID_TOKEN provider,"
                        + " so userinfo-url, emails-url and assume-email-verified mean nothing to it"
                        + " — set identity-source: USERINFO, or take them out");
            }
        }
        // what the sign-in button should say; defaults to the capitalised provider name
        if (isBlank(label)) {
            label = name.substring(0, 1).toUpperCase() + name.substring(1);
        }
        if (isBlank(scope)) {
            scope = "openid email";
        }
        if (isBlank(subjectField)) {
            subjectField = "sub";
        }
        if (isBlank(emailField)) {
            emailField = "email";
        }
        if (isBlank(emailVerifiedField)) {
            emailVerifiedField = "email_verified";
        }
    }

    private static void require(String value, String key) {
        if (isBlank(value)) {
            throw new IllegalArgumentException("an OAuth provider needs a " + key);
        }
    }

    /**
     * Present AND an absolute http(s) URL.
     *
     * <p>"Not blank" was the whole check, so {@code idp:8091/token} passed the boot and failed at
     * the callback instead — a 500 on the security origin, in the middle of somebody's sign-in, for
     * a missing scheme somebody typed weeks earlier. The place to notice a URL that is not a URL is
     * the start, where the deployment can still be corrected.
     */
    private static void requireUrl(String value, String key, String provider) {
        require(value, key);
        requireUrlIfPresent(value, key, provider);
    }

    private static void requireUrlIfPresent(String value, String key, String provider) {
        if (isBlank(value)) {
            return;
        }
        try {
            java.net.URI uri = java.net.URI.create(value.strip());
            if (uri.getScheme() == null || uri.getHost() == null
                    || !(uri.getScheme().equals("http") || uri.getScheme().equals("https"))) {
                throw new IllegalArgumentException("not an absolute http(s) URL");
            }
        } catch (RuntimeException notAUrl) {
            throw new IllegalArgumentException("provider '" + provider + "': " + key + " must be an"
                    + " absolute http(s) URL, not '" + value + "' (" + notAUrl.getMessage() + ")");
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
