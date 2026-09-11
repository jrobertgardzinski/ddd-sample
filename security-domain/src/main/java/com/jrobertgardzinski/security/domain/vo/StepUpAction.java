package com.jrobertgardzinski.security.domain.vo;

import java.util.Optional;

/**
 * The catalogue of actions a live session may take only after fresh proof: each one that hands
 * a session something durable, or changes what it takes to sign in later. A constant cannot
 * exist without the name it goes by on the wire (the request body and the elevation key), the
 * key its requirement is configured under, and the requirement the code ships - so an action
 * nobody registered does not compile, and none can quietly fall open.
 */
public enum StepUpAction {
    /** Closing an account is irreversible and takes the content with it. */
    DELETE_ACCOUNT("delete-account", StepUpRequirement.FULL_CHAIN),
    /** Resetting another account's factors strips that person's second factor. */
    ADMIN_RESET("admin-reset", StepUpRequirement.FULL_CHAIN),
    /** Closing SOMEBODY ELSE's account destroys their content on somebody else's say-so. */
    ADMIN_DELETE_ACCOUNT("admin-delete-account", StepUpRequirement.FULL_CHAIN),
    /** A factor added here decides every future sign-in. */
    ENROL_FACTOR("enrol-factor", StepUpRequirement.SECOND_FACTORS),
    /** A factor removed weakens every future sign-in. */
    REMOVE_FACTOR("remove-factor", StepUpRequirement.SECOND_FACTORS),
    /** Recovery codes are durable spare keys, usable when the factor is out of reach. */
    GENERATE_RECOVERY_CODES("generate-recovery-codes", StepUpRequirement.SECOND_FACTORS),
    /** Moving the address moves the account - the confirmation lands in the NEW mailbox. */
    CHANGE_EMAIL("change-email", StepUpRequirement.FULL_CHAIN),
    /** Granting a role is a permanent widening of what the session may do. */
    ADMIN_ROLES("admin-roles", StepUpRequirement.FULL_CHAIN),
    /** The password floor binds every future password in the estate. */
    ADMIN_SETTINGS("admin-settings", StepUpRequirement.FULL_CHAIN);

    private final String wire;
    private final StepUpRequirement defaultRequirement;

    StepUpAction(String wire, StepUpRequirement defaultRequirement) {
        this.wire = wire;
        this.defaultRequirement = defaultRequirement;
    }

    /** The name on the wire: the step-up request body, and the elevation key. */
    public String wire() {
        return wire;
    }

    /** The name its requirement goes by on every level of a deployment's configuration ladder. */
    public String key() {
        return "security.step.up." + wire.replace('-', '.');
    }

    /** The requirement the code ships: the rebuild level of this action's ladder. */
    public StepUpRequirement defaultRequirement() {
        return defaultRequirement;
    }

    public static Optional<StepUpAction> fromWire(String wire) {
        for (StepUpAction action : values()) {
            if (action.wire.equals(wire)) {
                return Optional.of(action);
            }
        }
        return Optional.empty();
    }
}
