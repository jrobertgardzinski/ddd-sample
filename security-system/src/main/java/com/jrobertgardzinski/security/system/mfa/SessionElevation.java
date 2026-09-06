package com.jrobertgardzinski.security.system.mfa;

import com.jrobertgardzinski.security.domain.vo.StepUpAction;
/**
 * A short-lived, one-shot "recently re-proven" mark for step-up authentication, keyed by the
 * caller's access token AND the action it was proven for. A sensitive action mints it after the
 * caller passes the step-up chain and consumes it once — so a stolen live session cannot quietly
 * delete an account: the thief would have to pass the step-up too. The action is part of the key on
 * purpose: an elevation earned for a cheap action (say {@code admin-reset} on a factor-less admin)
 * must NOT unlock {@code delete-account} — each sensitive endpoint consumes only the elevation
 * minted for its own action. In memory, TTL bounded (a lost mark just means proving again).
 */
public interface SessionElevation {

    void elevate(String accessToken, StepUpAction action);

    /** True and cleared if the token holds a live elevation for this action; false otherwise (one-shot). */
    boolean consume(String accessToken, StepUpAction action);
}
