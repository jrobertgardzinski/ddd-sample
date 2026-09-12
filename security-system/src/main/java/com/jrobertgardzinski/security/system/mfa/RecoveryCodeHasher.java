package com.jrobertgardzinski.security.system.mfa;

/**
 * How a RECOVERY code is turned into what the database holds — deliberately a different port from
 * {@link CodeHasher}, because the two codes have nothing in common but their shape.
 *
 * <p>A challenge code lives for minutes, is attempt-limited and is thrown away on use, so a plain
 * digest of it has nothing to chew on for long. A recovery code is a DURABLE credential: printed,
 * kept in a drawer, and good until it is spent — and it stands in for the whole factor chain. Ten
 * characters out of thirty-one is about 2^49 possibilities, which a single GPU sweeps through in
 * hours against an unsalted single-round digest; a stolen table would hand over every user's
 * break-glass keys at once.
 *
 * <p>Whatever implements this must therefore be keyed or slow (a server-held pepper, or a KDF) —
 * and a lookup by hash has to keep working, because that is how a code is spent.
 */
public interface RecoveryCodeHasher {

    String hash(String rawCode);
}
