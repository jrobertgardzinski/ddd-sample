package com.jrobertgardzinski.security.system.mfa;

import com.jrobertgardzinski.security.domain.vo.StepUpAction;
import com.jrobertgardzinski.email.domain.Email;

import java.util.Optional;

/**
 * Step-ups in flight, keyed by a one-shot ticket: who is stepping up, which session (access token)
 * to elevate on success, and the factor chain being walked. Short-lived, in memory — like the
 * sign-in pending store, a lost entry only means starting the step-up over.
 */
public interface StepUpStore {

    record StepUpPending(Email email, String accessToken, StepUpAction action, PendingAuthentication chain) {}

    String open(StepUpPending pending);

    Optional<StepUpPending> find(String ticket);

    void replace(String ticket, StepUpPending pending);

    void close(String ticket);
}
