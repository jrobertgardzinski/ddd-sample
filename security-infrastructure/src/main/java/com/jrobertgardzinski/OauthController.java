package com.jrobertgardzinski;

import com.jrobertgardzinski.security.config.oauth.OauthProviderSettings;
import com.jrobertgardzinski.security.domain.vo.ProviderIdentity;
import com.jrobertgardzinski.security.system.federation.FederatedSignIn;
import com.jrobertgardzinski.security.system.federation.FederatedSignInResult;
import io.micronaut.context.annotation.Value;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.QueryValue;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * HTTP entry points for social sign-in: {@code GET /oauth/{provider}/start} sends the browser to
 * the configured provider (Authorization Code + PKCE, S256), {@code GET /oauth/callback} receives
 * it back, exchanges the code server-side and drives the {@link FederatedSignIn} use case. On
 * success the browser is redirected to the {@code return} URL it asked for — the access token
 * rides in the URL FRAGMENT (never sent to any server; readable by the SPA), the refresh token in
 * the usual HttpOnly cookie. The return URL must match a configured prefix, otherwise the
 * redirect would be an open door for token exfiltration.
 */
// controllers do blocking work (JDBC, the provider's token endpoint) — keep it off the event loop
@ExecuteOn(TaskExecutors.BLOCKING)
@Controller("/oauth")
final class OauthController {

    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(OauthController.class);

    /**
     * Binds a dance to the browser that started it.
     *
     * <p>{@code state} is a server-side key, and until this cookie existed it was the ONLY thing
     * the callback checked — so a callback URL was a bearer token for somebody else's sign-in.
     * An attacker could start a dance, keep the link, and get a victim to open it: the victim's
     * browser then received a session belonging to the ATTACKER's provider identity, which is
     * session fixation — anything the victim did next, they did in the attacker's account. Sent
     * SameSite=Lax on purpose: the callback arrives as a top-level navigation from the provider,
     * which Strict would not carry.
     */
    private static final String STATE_COOKIE = "oauth_state";

    private final Map<String, OauthProviderSettings> providers;
    private final OauthFlowStore flows;
    private final OidcClient oidc;
    private final FederatedSignIn federatedSignIn;
    private final RefreshCookies refreshCookies;
    private final TransactionBoundary transactionBoundary;
    private final List<String> allowedReturnPrefixes;
    private final boolean secureCookies;

    OauthController(List<OauthProviderSettings> providers, OauthFlowStore flows, OidcClient oidc,
                    FederatedSignIn federatedSignIn, RefreshCookies refreshCookies,
                    TransactionBoundary transactionBoundary,
                    @Value("${security.oauth.allowed-return-prefixes:http://localhost:8083/}")
                    List<String> allowedReturnPrefixes,
                    @Value("${security.cookie.secure:true}") boolean secureCookies) {
        this.secureCookies = secureCookies;
        this.providers = providers.stream()
                .collect(java.util.stream.Collectors.toMap(OauthProviderSettings::name, p -> p));
        this.flows = flows;
        this.oidc = oidc;
        this.federatedSignIn = federatedSignIn;
        this.refreshCookies = refreshCookies;
        this.transactionBoundary = transactionBoundary;
        // A RAW startsWith on a prefix without a trailing slash is not a host check: the natural
        // thing to configure ("http://app.example.com") also admits http://app.example.com.evil.net/
        // and http://app.example.com@evil.net/ — both of which would then RECEIVE the access token
        // in their fragment. Normalising every prefix to end in "/" makes the comparison stop at a
        // path boundary, so a longer host can no longer wear a shorter one as its prefix.
        this.allowedReturnPrefixes = allowedReturnPrefixes.stream()
                .filter(prefix -> !prefix.isBlank())
                .map(prefix -> prefix.endsWith("/") ? prefix : prefix + "/")
                .toList();
    }

    /** The configured providers, for the UI to draw its sign-in buttons from — adding a provider
     * to the config is all it takes for a new button to appear. */
    @Get(value = "/providers", produces = MediaType.APPLICATION_JSON)
    HttpResponse<?> providers() {
        return HttpResponse.ok(Map.of("providers", providers.values().stream()
                .sorted(java.util.Comparator.comparing(OauthProviderSettings::name))
                .map(p -> Map.of("name", p.name(), "label", p.label()))
                .toList()));
    }

    @Get(value = "/{provider}/start", produces = MediaType.APPLICATION_JSON)
    HttpResponse<?> start(@PathVariable String provider,
                          @Nullable @QueryValue("return") String returnUrl) {
        OauthProviderSettings config = providers.get(provider);
        if (config == null) {
            return HttpResponse.notFound(Refusal.alsoAsError("UNKNOWN_PROVIDER"));
        }
        String destination = returnUrl != null ? returnUrl : allowedReturnPrefixes.get(0);
        // the prefix itself, with no path after it, is the destination the default names — compare
        // it with the trailing slash present, which is how the prefixes are held
        String compared = destination.endsWith("/") ? destination : destination + "/";
        if (allowedReturnPrefixes.stream().noneMatch(compared::startsWith)) {
            return HttpResponse.badRequest(Refusal.alsoAsError("RETURN_URL_NOT_ALLOWED"));
        }
        String codeVerifier = OauthFlowStore.randomToken();
        String nonce = OauthFlowStore.randomToken();
        String state = flows.begin(provider, codeVerifier, nonce, destination);
        String location = config.authorizeUrl() + "?" + query(Map.of(
                "response_type", "code",
                "client_id", config.clientId(),
                "redirect_uri", config.redirectUri(),
                "scope", config.scope(),
                "state", state,
                "nonce", nonce,
                "code_challenge", s256(codeVerifier),
                "code_challenge_method", "S256"));
        return HttpResponse.status(HttpStatus.FOUND).header("Location", location)
                .cookie(stateCookie(state));
    }

    @Get(value = "/callback", produces = MediaType.APPLICATION_JSON)
    HttpResponse<?> callback(HttpRequest<?> request, @Nullable @QueryValue String state,
                             @Nullable @QueryValue String code, @Nullable @QueryValue String error) {
        // the browser that started the dance is the only one allowed to finish it
        String bound = request.getCookies().findCookie(STATE_COOKIE).map(Cookie::getValue).orElse(null);
        if (state == null || bound == null || !MessageDigest.isEqual(
                bound.getBytes(StandardCharsets.UTF_8), state.getBytes(StandardCharsets.UTF_8))) {
            // no flow is consumed: a callback handed to somebody else must not spend the attacker's
            // state either, and there is no return URL here that can be trusted
            return HttpResponse.badRequest(Refusal.alsoAsError("STATE_NOT_BOUND_TO_THIS_BROWSER"))
                    .cookie(clearedStateCookie());
        }
        OauthFlowStore.PendingFlow flow = flows.consume(state).orElse(null);
        if (flow == null) {
            // no flow, no return URL to trust — a bare refusal is all this callback can say
            return HttpResponse.badRequest(Refusal.alsoAsError("UNKNOWN_OR_EXPIRED_STATE"));
        }
        if (error != null || code == null) {
            return backTo(flow.returnUrl(), "#oauthError=" + encode(error != null ? error : "missing_code"))
                    .cookie(clearedStateCookie());
        }
        ProviderIdentity identity;
        try {
            identity = oidc.identityFrom(providers.get(flow.provider()), code, flow.codeVerifier(),
                    flow.nonce());
        } catch (RuntimeException refused) {
            // RuntimeException too, and deliberately: what the provider sends is not ours to trust.
            // An id_token with a dotless e-mail domain or a non-numeric exp threw out of here and
            // answered 500 ON THE SECURITY ORIGIN, echoing the provider's data in the body — while
            // the browser sat on a page that was supposed to redirect. The user's situation is the
            // same in every one of those cases: the sign-in did not happen.
            LOG.warn("federated sign-in through {} failed: {}", flow.provider(), refused.toString());
            return backTo(flow.returnUrl(), "#oauthError=SIGN_IN_FAILED").cookie(clearedStateCookie());
        }
        FederatedSignInResult result = transactionBoundary.execute(() -> federatedSignIn.execute(identity));
        return switch (result) {
            case FederatedSignInResult.SignedIn signedIn -> backTo(flow.returnUrl(),
                    "#accessToken=" + encode(signedIn.session().plainAccessToken()))
                    .cookie(refreshCookies.issue(signedIn.session().plainRefreshToken()))
                    .cookie(clearedStateCookie());
            // the account has enrolled factors: hand the ticket back so the UI can finish the chain
            // through /authenticate/factor, exactly like a password sign-in
            case FederatedSignInResult.MfaRequired mfa -> backTo(flow.returnUrl(),
                    "#mfaTicket=" + encode(mfa.ticket()) + "&nextFactor=" + encode(mfa.nextFactor().value())
                            + (mfa.challengeData() == null ? "" : "&challengeData=" + encode(mfa.challengeData())));
            case FederatedSignInResult.Refused refused ->
                    backTo(flow.returnUrl(), "#oauthError=" + encode(refused.reason()));
        };
    }

    /**
     * Back to the app, with what happened in the fragment.
     *
     * <p>A return URL may already carry one (it is the app's own state, and it survives the round
     * trip through the provider), so appending {@code #accessToken=...} to it produced a location
     * with two '#' — everything after the second one is part of the FIRST fragment's value, and the
     * SPA read neither. When there is a fragment already, ours is appended to it with '&amp;', which
     * is how a fragment carries more than one pair.
     */
    private static io.micronaut.http.MutableHttpResponse<?> backTo(String returnUrl, String fragment) {
        String separator = returnUrl.contains("#") ? "&" : "";
        String location = separator.isEmpty()
                ? returnUrl + fragment
                : returnUrl + separator + fragment.substring(1);   // drop our own '#'
        return HttpResponse.status(HttpStatus.FOUND).header("Location", location);
    }

    /** Lives as long as a flow may (the store's own TTL is ten minutes) and no longer. */
    private Cookie stateCookie(String state) {
        return Cookie.of(STATE_COOKIE, state)
                .httpOnly(true)
                .secure(secureCookies)
                .sameSite(io.micronaut.http.cookie.SameSite.Lax)
                .path("/oauth")
                .maxAge(java.time.Duration.ofMinutes(10));
    }

    private static Cookie clearedStateCookie() {
        return Cookie.of(STATE_COOKIE, "").httpOnly(true).sameSite(io.micronaut.http.cookie.SameSite.Lax)
                .path("/oauth").maxAge(0);
    }

    private static String s256(String verifier) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static String query(Map<String, String> params) {
        return params.entrySet().stream()
                .map(e -> e.getKey() + "=" + encode(e.getValue()))
                .collect(java.util.stream.Collectors.joining("&"));
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
