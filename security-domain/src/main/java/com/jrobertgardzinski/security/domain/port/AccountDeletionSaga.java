package com.jrobertgardzinski.security.domain.port;

import com.jrobertgardzinski.security.domain.vo.AccountClosure;

/**
 * Outbound port that starts the cross-service part of closing an account: other services purge
 * the user's content, and their confirmation (or its absence) decides whether the deletion
 * completes or rolls back. How the request travels (an event, a queue) is the adapter's business.
 *
 * <p>The whole request travels as one {@link AccountClosure}, because the legal basis of the
 * closure is not a label beside it: the content services may honour its choices only when
 * somebody other than the data subject asked.
 */
public interface AccountDeletionSaga {

    void begin(AccountClosure closure);
}
