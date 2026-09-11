package com.jrobertgardzinski.security.domain.vo;

import com.jrobertgardzinski.email.domain.Email;

/**
 * One request to close one account — and the place where the rule about WHOSE account it is lives,
 * once, instead of being spread over the endpoints that start such a request.
 *
 * <p>Two kinds, and the difference is not a flag but a legal basis. {@link #requestedByOwner} is
 * the data subject exercising the right to erasure: everything they posted goes, and the
 * conditions under which content may survive are not theirs to state, because the exceptions to
 * that right are enumerated by law and "the community up-voted it" is not among them.
 * {@link #requestedByAdministrator} is the controller of the data acting on its own decision — a
 * ban, house rules — where nobody is exercising any right, so what happens to each kind of content
 * is an ordinary business choice that rides along.
 *
 * <p><strong>A closure that breaks that rule cannot be built.</strong> The canonical constructor
 * drops the choices of an owner's request rather than trusting every caller to send none — so a
 * controller that forwards a body it should have ignored, a test that hands over a stale object,
 * or a new entry point written next year all produce the lawful request instead of a quiet
 * exception to somebody's erasure.
 *
 * <p>{@code choices} stays opaque: the axis names and the rule strings belong to the content
 * services' vocabulary, and identity only carries the map.
 */
public record AccountClosure(Email target, DeletionInitiator requestedBy, PurgeChoices choices) {

    public AccountClosure {
        if (requestedBy == DeletionInitiator.SELF) {
            choices = PurgeChoices.serviceDefaults();
        }
    }

    /** The account's own owner asking to be forgotten: no conditions, now or ever. */
    public static AccountClosure requestedByOwner(Email target) {
        return new AccountClosure(target, DeletionInitiator.SELF, PurgeChoices.serviceDefaults());
    }

    /** An administrator closing somebody else's account, saying what happens to their content. */
    public static AccountClosure requestedByAdministrator(Email target, PurgeChoices choices) {
        return new AccountClosure(target, DeletionInitiator.ADMIN, choices);
    }
}
