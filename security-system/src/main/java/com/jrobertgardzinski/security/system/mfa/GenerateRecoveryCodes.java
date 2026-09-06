package com.jrobertgardzinski.security.system.mfa;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.config.mfa.RecoveryCodeConfig;
import com.jrobertgardzinski.security.domain.repository.RecoveryCodeRepository;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Mints a fresh batch of recovery codes for a user: the plain codes are returned exactly once —
 * to be shown, printed and never seen again — while only their hashes are stored. Generating a
 * new batch invalidates the old one, so a leaked printout is answered by regenerating.
 *
 * <p>The alphabet drops the look-alikes (0/o, 1/l/i) because these codes live on paper; a code is
 * grouped with hyphens for the same reason. Verification normalises case and hyphens away, so a
 * user may type it however their printout looks.
 */
public class GenerateRecoveryCodes {

    private static final char[] ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789".toCharArray();
    private static final int GROUP = 5;

    private final RecoveryCodeRepository repository;
    private final CodeHasher hasher;
    private final RecoveryCodeConfig config;
    private final SecureRandom random = new SecureRandom();

    public GenerateRecoveryCodes(RecoveryCodeRepository repository, CodeHasher hasher,
                                 RecoveryCodeConfig config) {
        this.repository = repository;
        this.hasher = hasher;
        this.config = config;
    }

    /** The plain codes, shown once; the repository keeps only their normalised hashes. */
    public List<String> execute(Email userEmail) {
        List<String> plain = new ArrayList<>(config.count().value());
        for (int i = 0; i < config.count().value(); i++) {
            plain.add(mint());
        }
        repository.replaceAll(userEmail,
                plain.stream().map(code -> hasher.hash(normalise(code))).toList());
        return List.copyOf(plain);
    }

    /** Case and hyphens carry no information — strip them before hashing, on both ends. */
    public static String normalise(String code) {
        return code.replace("-", "").trim().toLowerCase();
    }

    private String mint() {
        StringBuilder code = new StringBuilder(config.length().value() + config.length().value() / GROUP);
        for (int i = 0; i < config.length().value(); i++) {
            if (i > 0 && i % GROUP == 0) {
                code.append('-');
            }
            code.append(ALPHABET[random.nextInt(ALPHABET.length)]);
        }
        return code.toString();
    }
}
