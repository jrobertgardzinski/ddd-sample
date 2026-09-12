package com.jrobertgardzinski;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.port.AccessTokenMint;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.Role;
import com.jrobertgardzinski.security.domain.vo.token.AccessToken;
import com.jrobertgardzinski.security.domain.vo.token.expiration.AuthorizationTokenExpiration;
import io.micronaut.context.annotation.Value;
import io.micronaut.json.JsonMapper;
import jakarta.inject.Singleton;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Mints access tokens as self-contained JWTs (EdDSA over Ed25519, plain JDK crypto — no extra
 * dependency). The claims — subject e-mail, roles, expiry — let OTHER services verify a caller
 * offline against {@code /.well-known/jwks.json} instead of calling {@code /me}; the trade-off is
 * theirs to make: offline verification cannot see a logout or a role change until the token
 * expires, introspection can. Security itself keeps treating the value as an opaque secret
 * (hashed, stored, compared), so its own logout and revoke-all stay instant.
 *
 * <p>Keys come from {@code security.jwt.private-key} / {@code security.jwt.public-key} (base64,
 * PKCS#8 / X.509 DER); when absent a fresh pair is generated at startup — fine for dev and tests,
 * where a restart invalidating offline verification only fails towards safety (the introspection
 * path keeps working, it is DB-backed).
 *
 * <p>Rotation with overlap: {@code security.jwt.previous-public-keys} (comma-separated base64
 * X.509) keeps the retired keys' public halves in the served JWK set while tokens they signed are
 * still alive. The procedure is config-only — mint a new pair, move the old public key onto the
 * previous list, deploy; drop it from the list once the longest access-token TTL has passed.
 * Only public halves ride along: a retired private key can be destroyed at rotation time.
 */
@Singleton
class JwtAccessTokenMint implements AccessTokenMint {

    static final String ISSUER = "microservice-security";

    private final KeyPair keyPair;
    private final String keyId;
    private final List<PublicKey> previousPublicKeys;
    private final com.jrobertgardzinski.security.system.roles.RequireRole roles;
    private final com.jrobertgardzinski.security.system.mfa.MfaCompliance compliance;
    private final Clock clock;
    private final JsonMapper json;

    JwtAccessTokenMint(@Value("${security.jwt.private-key:}") String privateKeyBase64,
                       @Value("${security.jwt.public-key:}") String publicKeyBase64,
                       @Value("${security.jwt.previous-public-keys:}") String previousPublicKeysBase64,
                       com.jrobertgardzinski.security.system.roles.RequireRole roles,
                       com.jrobertgardzinski.security.system.mfa.MfaCompliance compliance,
                       Clock clock, JsonMapper json) {
        this.keyPair = load(privateKeyBase64, publicKeyBase64);
        this.keyId = keyIdOf(keyPair.getPublic());
        this.previousPublicKeys = loadPublicKeys(previousPublicKeysBase64);
        this.roles = roles;
        this.compliance = compliance;
        this.clock = clock;
        this.json = json;
    }

    @Override
    public AccessToken mint(Email email, AuthorizationTokenExpiration expiration) {
        // the roles IN FORCE, which include the ADMIN a bootstrap administrator holds by
        // configuration rather than by a row — the claim other services gate on must say the same
        // thing /admin/** does
        java.util.Set<Role> roleSet = this.roles.rolesInForce(email);
        List<String> roles = roleSet.stream().map(Role::name).sorted().toList();
        Map<String, Object> header = Map.of("alg", "EdDSA", "typ", "JWT", "kid", keyId);
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", ISSUER);
        claims.put("sub", email.value());
        claims.put("roles", roles);
        // whether the account meets its role's factor floor AT MINT TIME — offline consumers use
        // it to withhold privileged roles from an under-enrolled caller. Same trade-off as the
        // rest of the claims: enrolment mid-session shows after the next sign-in/refresh.
        claims.put("mfaCompliant", compliance.isCompliant(email, roleSet));
        claims.put("iat", clock.instant().getEpochSecond());
        claims.put("exp", expiration.value().atZone(clock.getZone()).toEpochSecond());
        claims.put("jti", UUID.randomUUID().toString());

        String signingInput = base64Url(toJson(header)) + "." + base64Url(toJson(claims));
        return new AccessToken(signingInput + "." + base64Url(sign(signingInput)));
    }

    /**
     * The signing key's public half plus any still-overlapping retired keys, as JWKs — what
     * {@code /.well-known/jwks.json} serves to offline verifiers. The current key comes first;
     * verifiers pick by {@code kid} anyway.
     */
    List<Map<String, Object>> publicJwks() {
        List<Map<String, Object>> keys = new java.util.ArrayList<>();
        keys.add(jwkOf(keyPair.getPublic()));
        for (PublicKey retired : previousPublicKeys) {
            keys.add(jwkOf(retired));
        }
        return List.copyOf(keys);
    }

    private static Map<String, Object> jwkOf(PublicKey publicKey) {
        return Map.of(
                "kty", "OKP",
                "crv", "Ed25519",
                "x", base64Url(rawPublicKey(publicKey)),
                "kid", keyIdOf(publicKey),
                "alg", "EdDSA",
                "use", "sig");
    }

    private byte[] sign(String signingInput) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(keyPair.getPrivate());
            signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 signing failed", e);
        }
    }

    private byte[] toJson(Map<String, Object> value) {
        try {
            return json.writeValueAsBytes(value);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static KeyPair load(String privateKeyBase64, String publicKeyBase64) {
        try {
            if (privateKeyBase64.isBlank() || publicKeyBase64.isBlank()) {
                return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            }
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
            PrivateKey privateKey = keyFactory.generatePrivate(
                    new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyBase64)));
            PublicKey publicKey = keyFactory.generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyBase64)));
            return new KeyPair(publicKey, privateKey);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("could not load the JWT signing keys", e);
        }
    }

    private static List<PublicKey> loadPublicKeys(String commaSeparatedBase64) {
        if (commaSeparatedBase64.isBlank()) {
            return List.of();
        }
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
            List<PublicKey> keys = new java.util.ArrayList<>();
            for (String encoded : commaSeparatedBase64.split(",")) {
                if (!encoded.isBlank()) {
                    keys.add(keyFactory.generatePublic(
                            new X509EncodedKeySpec(Base64.getDecoder().decode(encoded.trim()))));
                }
            }
            return List.copyOf(keys);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("could not load the previous JWT public keys", e);
        }
    }

    /** The 32 raw Ed25519 bytes — the X.509 encoding is a fixed 12-byte DER prefix plus these. */
    private static byte[] rawPublicKey(PublicKey publicKey) {
        byte[] encoded = publicKey.getEncoded();
        byte[] raw = new byte[32];
        System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
        return raw;
    }

    private static String keyIdOf(PublicKey publicKey) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
            return HexFormat.of().formatHex(digest, 0, 8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
