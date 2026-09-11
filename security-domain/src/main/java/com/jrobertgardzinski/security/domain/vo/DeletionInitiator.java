package com.jrobertgardzinski.security.domain.vo;

/**
 * Who asked for an account to be closed — and therefore under what legal basis it is closed.
 *
 * <p>{@link #SELF} is the data subject exercising the right to erasure: the conditions under which
 * content may survive are not the caller's to choose, because the exceptions to that right are
 * enumerated by law and "this meme is popular" is not among them. A self-deletion therefore states
 * NO purge conditions — {@link PurgeChoices#serviceDefaults()} is the only thing it can carry — and
 * the content services refuse anything but destruction when they see this value, whatever their own
 * defaults or an operator's override say.
 *
 * <p>{@link #ADMIN} is the controller of the data acting on its own decision (a ban, house rules).
 * Nobody exercised a right, so conditions ARE a business choice and ride the saga: keep what the
 * community made popular, keep it without its author, or destroy it.
 *
 * <p>The distinction travels on the wire as this name and nothing more. WHICH administrator pressed
 * the button is security's own audit line: three content services would gain an extra address to
 * hold, and not one of them has a use for it.
 */
public enum DeletionInitiator {

    SELF,
    ADMIN;

    /** The name this initiator goes by on the deletion fact and the purge commands. */
    public String wire() {
        return name();
    }
}
