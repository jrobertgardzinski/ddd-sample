package com.jrobertgardzinski.security.system.account;

import com.jrobertgardzinski.email.config.CanRegisterConfig;
import com.jrobertgardzinski.email.domain.Email;
import com.jrobertgardzinski.email.domain.NormalizedEmail;
import com.jrobertgardzinski.security.domain.port.EmailVerificationNotifier;
import com.jrobertgardzinski.security.domain.repository.EmailChangeRepository;
import com.jrobertgardzinski.security.domain.repository.UserRepository;
import com.jrobertgardzinski.security.domain.vo.EmailChange;
import com.jrobertgardzinski.security.domain.vo.token.VerificationToken;

/**
 * Starts an email change for a signed-in user: refuses an address this deployment does not admit,
 * refuses one that is already taken, and otherwise mints a verification token, remembers the
 * pending change, and e-mails the link to the new address (ownership must be proven before the
 * change takes effect).
 *
 * <p>The e-mail policy is asked FIRST, and asked here rather than only at registration: the two
 * questions are the same question. A deployment that admits only company addresses, or refuses
 * disposable ones, was letting an account walk out of that rule the moment it existed — the change
 * takes roles, factors and federated links with it. The refusal carries the broken rules and the
 * policy in force, the same shape registration answers with.
 */
public class RequestEmailChange {

    private final UserRepository userRepository;
    private final EmailChangeRepository emailChangeRepository;
    private final EmailVerificationNotifier notifier;
    private final CanRegisterConfig emailPolicy;

    public RequestEmailChange(UserRepository userRepository, EmailChangeRepository emailChangeRepository,
                              EmailVerificationNotifier notifier, CanRegisterConfig emailPolicy) {
        this.userRepository = userRepository;
        this.emailChangeRepository = emailChangeRepository;
        this.notifier = notifier;
        this.emailPolicy = emailPolicy;
    }

    public RequestEmailChangeResult execute(Email currentEmail, Email newEmail) {
        _NewEmailVerdict verdict = _NewEmailVerdict.judge(emailPolicy, newEmail);
        if (!verdict.accepted()) {
            return new RequestEmailChangeResult.Rejected(verdict.errorCodes(), emailPolicy);
        }
        if (userRepository.existsBy(NormalizedEmail.of(newEmail))) {
            return new RequestEmailChangeResult.EmailTaken();
        }
        VerificationToken token = VerificationToken.random();
        emailChangeRepository.startChange(new EmailChange(currentEmail, newEmail), token);
        notifier.sendVerificationLink(newEmail, token);
        return new RequestEmailChangeResult.Requested();
    }
}
