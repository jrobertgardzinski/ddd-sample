package com.jrobertgardzinski.security.system.account;

import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.security.domain.port.AccountDeletionSaga;
import com.jrobertgardzinski.security.domain.repository.AuthorizationDataRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.AccountClosure;

/**
 * Opens the account-closure saga (GDPR right to be forgotten): the account locks at once — every
 * session revoked, sign-in refused — and the user's content elsewhere is asked to be purged. The
 * final deletion happens only when that purge confirms ({@link DeleteAccount}); no confirmation
 * in time rolls the lock back.
 */
public class StartAccountDeletion {

    private final UserRepository userRepository;
    private final AuthorizationDataRepository authorizationDataRepository;
    private final AccountDeletionSaga saga;

    public StartAccountDeletion(UserRepository userRepository,
                                AuthorizationDataRepository authorizationDataRepository,
                                AccountDeletionSaga saga) {
        this.userRepository = userRepository;
        this.authorizationDataRepository = authorizationDataRepository;
        this.saga = saga;
    }

    public void execute(AccountClosure closure) {
        Email email = closure.target();
        authorizationDataRepository.revokeAllSessions(email);
        userRepository.markPendingDeletion(email);
        saga.begin(closure);
    }
}
