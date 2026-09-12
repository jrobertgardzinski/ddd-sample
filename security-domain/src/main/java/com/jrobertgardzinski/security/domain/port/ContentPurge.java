package com.jrobertgardzinski.security.domain.port;

import com.jrobertgardzinski.security.domain.vo.AccountClosure;

/**
 * Getting rid of everything a leaver posted, wherever it lives.
 *
 * <p>The port is named after the WORK, not after the machinery that carries it out, and that
 * distinction is the whole reason it exists. This service knows one thing about the content: it
 * has to go, and the account may not be deleted until it has. Which is a statement about the law
 * and about nothing else.
 *
 * <p>There are two honest ways to do it, and they are not variations of one design:
 *
 * <ul>
 *   <li><strong>Across services</strong> — a saga. The content lives in other processes with other
 *       databases, so there is no shared transaction to lean on: a command goes out, every
 *       participant confirms, a quorum closes the case, a timeout compensates it, and a verdict
 *       comes back. That is what {@code AccountDeletionOrchestrator} does, and the ~900 lines it
 *       takes are the price of the distribution, not of the deletion.</li>
 *   <li><strong>In one process</strong> — a transaction. With one database the same work is a few
 *       deletes that either all happen or none do, and every part of the saga above becomes
 *       unnecessary: no confirmations, no quorum, no retry budget, nothing to compensate.</li>
 * </ul>
 *
 * <p>Two things stay true in both, and they are the reason even the monolith is not purely a
 * transaction: <strong>an image leaving object storage and a mail being sent cannot join it.</strong>
 * Both need something durable that survives a crash after the commit.
 *
 * <p>{@link #begin} is deliberately "make it so" rather than "do it now": the distributed answer
 * arrives minutes later through a listener, while a transactional one would be finished before the
 * method returns. Both are allowed — the saga store's STARTED→COMPLETED latch is idempotent and
 * does not care whether a second passed or eight minutes.
 *
 * <p>The whole request travels as one {@link AccountClosure}, because the legal basis of the
 * closure is not a label beside it: the content services may honour its choices only when somebody
 * other than the data subject asked.
 */
public interface ContentPurge {

    void begin(AccountClosure closure);
}
