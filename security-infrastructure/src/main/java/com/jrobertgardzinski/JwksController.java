package com.jrobertgardzinski;

import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;

import java.util.Map;

/**
 * The public half of the access-token signing key, as a standard JWK Set. Other services fetch it
 * once (and on an unknown {@code kid}) to verify access-token signatures offline instead of
 * calling {@code /me} — trading revocation awareness for a saved round-trip; the token's
 * {@code exp} bounds how stale they can be.
 *
 * <p>During a key rotation the set also carries the retired keys still inside their overlap
 * window ({@code security.jwt.previous-public-keys}), so tokens signed before the rotation keep
 * verifying until they expire.
 */
@Controller("/.well-known")
final class JwksController {

    private final JwtAccessTokenMint mint;

    JwksController(JwtAccessTokenMint mint) {
        this.mint = mint;
    }

    /**
     * Cacheable for an hour, and that number is a statement about rotation rather than a
     * performance setting: a verifier that holds this set for an hour will keep verifying tokens
     * signed with a key retired inside that hour — which is exactly what the overlap window is for
     * — and will come back for a {@code kid} it does not know anyway. Without the header every
     * verifier decided for itself, and the ones that decided "never" asked on every single token.
     */
    @Get(value = "/jwks.json", produces = MediaType.APPLICATION_JSON)
    HttpResponse<Map<String, Object>> jwks() {
        return HttpResponse.ok(Map.<String, Object>of("keys", mint.publicJwks()))
                .header("Cache-Control", "public, max-age=3600");
    }
}
