package com.jrobertgardzinski.security.domain.repository;

import com.jrobertgardzinski.security.domain.entity.AuthenticationBlock;
import com.jrobertgardzinski.security.domain.vo.Source;

import java.util.Optional;

public interface AuthenticationBlockRepository {

    /**
     * Place the block for this source — REPLACING any block it already has, rather than adding a
     * second one. At most one block exists per address: the guard writes a fresh one the moment a
     * limit is reached, and a source that is blocked again while a block stands gets the new expiry,
     * not two rows to argue about.
     *
     * <p>Every adapter has always behaved this way; the port simply did not say so, which left the
     * next adapter free to guess differently — and the JDBC one used to spell it as delete-then-save,
     * which is how two requests crossing the threshold together collided on the key.
     */
    AuthenticationBlock create(AuthenticationBlock authenticationBlock);
    void removeAllFor(Source source);
    Optional<AuthenticationBlock> findBy(Source source);
}
