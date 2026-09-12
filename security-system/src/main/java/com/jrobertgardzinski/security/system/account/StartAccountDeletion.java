package com.jrobertgardzinski.security.system.account;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.port.ContentPurge;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.AccountClosure;

/**
 * Closes an account (GDPR right to be forgotten): the account locks at once — every session
 * revoked, sign-in refused — and the user's content is asked to go. The final deletion happens
 * only once that purge is done ({@link DeleteAccount}); a purge that never finishes rolls the lock
 * back.
 *
 * <p>This use case does not know, and must not, whether the content lives in other services or in
 * the same process — see {@link ContentPurge}. It states the closure and waits; whether the answer
 * comes back in a millisecond or in eight minutes is the adapter's business.
 */
public class StartAccountDeletion {

    private final UserRepository userRepository;
    private final AuthorizationDataRepository authorizationDataRepository;
    private final ContentPurge contentPurge;

    public StartAccountDeletion(UserRepository userRepository,
                                AuthorizationDataRepository authorizationDataRepository,
                                ContentPurge contentPurge) {
        this.userRepository = userRepository;
        this.authorizationDataRepository = authorizationDataRepository;
        this.contentPurge = contentPurge;
    }

    public void execute(AccountClosure closure) {
        Email email = closure.target();
        authorizationDataRepository.revokeAllSessions(email);
        userRepository.markPendingDeletion(email);
        contentPurge.begin(closure);
    }
}
