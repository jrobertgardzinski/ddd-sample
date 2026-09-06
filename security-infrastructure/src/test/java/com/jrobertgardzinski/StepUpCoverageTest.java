package com.jrobertgardzinski;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A law, in the spirit of ADR 0006: every HTTP entry point is CLASSIFIED — it either sits behind a
 * step-up, or it is exempt for a reason written down here.
 *
 * <p>P18 found the family this closes. {@code docs/mfa-design.md} declared the step-up phase DONE
 * and named enrolment, factor removal and password change as covered; the code had it on exactly
 * one endpoint. Nothing failed, because nothing was checking — a promise in a design document is
 * not a mechanism. This test is the mechanism: add a controller and the build asks you which of the
 * two things it is, before anyone has to notice.
 *
 * <p>What "sensitive" means here is narrow and testable: the request, made with nothing but a LIVE
 * SESSION, changes what it takes to sign in later, or hands out a durable new way in. That is the
 * shape of a stolen session turning itself into permanent access, and the shape step-up exists to
 * stop. Reading data, ending a session, or anything that already demands a secret the thief does
 * not have (the current password, a token mailed to an address they do not control) is exempt.
 */
class StepUpCoverageTest {

    private static final List<Path> CONTROLLERS = List.of(Path.of("src/main/java/com/jrobertgardzinski"));

    /**
     * Endpoints that must be behind a step-up, each with the durable access it would otherwise
     * hand a thief holding nothing but a live session.
     */
    private static final Map<String, String> MUST_STEP_UP = Map.of(
            "DeleteAccountController", "closing an account is irreversible and takes the content with it",
            "FactorsController", "a factor added here decides every future sign-in — and a factor removed weakens it",
            "AdminFactorsController", "resetting another account's factors strips that person's second factor",
            "RecoveryCodesController", "recovery codes are durable spare keys: minted once, usable when the factor is out of reach",
            "EmailChangeController", "moving the address moves the account — the confirmation lands in the NEW mailbox",
            "AdminRolesController", "granting a role is a permanent widening of what the session may do",
            "AdminPasswordPolicyController", "the password floor binds every future password in the estate — lowering it on a stolen live session is a lasting weakening");

    /**
     * The rest, each with the reason a live session is enough. These are not oversights; leaving
     * the reason unwritten is how the last gap survived a design document that claimed otherwise.
     */
    private static final Map<String, String> EXEMPT = Map.ofEntries(
            Map.entry("AuthenticationController", "the way IN — there is no elevated session to demand yet"),
            Map.entry("AuthFactorController", "continues a sign-in that has not produced a session yet"),
            Map.entry("StepUpController", "IS the step-up; demanding one to obtain one is a closed loop"),
            Map.entry("RefreshController", "renews an existing session and grants nothing new"),
            Map.entry("LogoutController", "ends a session: the safe direction, and a thief gains nothing by it"),
            Map.entry("SessionsController", "listing and revoking one's own sessions — the remedy, not the risk"),
            Map.entry("MeController", "reads the caller's own profile"),
            Map.entry("JwksController", "serves public verification keys"),
            Map.entry("SecurityController", "registration and the verification mail — no session is involved"),
            Map.entry("VerifyEmailController", "consumes a token mailed to the address being verified"),
            Map.entry("PasswordResetController", "consumes a token mailed to the account's address, which a session thief does not hold"),
            Map.entry("ConfirmEmailChangeController", "consumes a token mailed to the NEW address; the change itself is guarded where it STARTS"),
            Map.entry("ChangePasswordController", "verifies the CURRENT password inline — a secret the session thief does not have"),
            Map.entry("OauthController", "the federated way in; no session exists to elevate"),
            Map.entry("TestMailboxController", "test environment only (@Requires(env = \"test\")) and never deployed"));

    @Test
    void every_controller_is_either_behind_step_up_or_exempt_for_a_written_reason() throws IOException {
        Set<String> classified = new TreeSet<>(MUST_STEP_UP.keySet());
        classified.addAll(EXEMPT.keySet());

        Set<String> found = controllers();

        Set<String> unclassified = found.stream()
                .filter(name -> !classified.contains(name))
                .collect(Collectors.toCollection(TreeSet::new));
        assertTrue(unclassified.isEmpty(),
                "a new HTTP entry point appeared and nobody said which it is — put it in MUST_STEP_UP"
                        + " with the durable access it grants, or in EXEMPT with the reason a live"
                        + " session is enough: " + unclassified);

        Set<String> vanished = classified.stream()
                .filter(name -> !found.contains(name))
                .collect(Collectors.toCollection(TreeSet::new));
        assertTrue(vanished.isEmpty(),
                "these are classified but no longer exist — the list is drifting into fiction: " + vanished);
    }

    @Test
    void everything_that_must_step_up_actually_does() throws IOException {
        List<String> unguarded = MUST_STEP_UP.entrySet().stream()
                .filter(entry -> !guards(entry.getKey()))
                .map(entry -> entry.getKey() + " (" + entry.getValue() + ")")
                .toList();

        assertEquals(List.of(), unguarded,
                "these endpoints hand a live session durable access and ask for no fresh proof —"
                        + " which is exactly how a stolen session becomes permanent");
    }

    /**
     * The catalogue and the endpoints agree: every {@link StepUpAction} is consumed by some
     * controller (a constant nobody guards with is a requirement the deployment configures for
     * nothing), and every endpoint that must step up names its action from the catalogue - the
     * only way an action reaches the policy, so a string that is not in the catalogue cannot
     * quietly fall to the strictest requirement, or to none.
     */
    @Test
    void the_catalogue_of_actions_and_the_endpoints_agree() throws IOException {
        Map<String, String> sources = new java.util.TreeMap<>();
        try (Stream<Path> files = walkAll()) {
            files.filter(path -> path.getFileName().toString().endsWith("Controller.java"))
                    .forEach(path -> sources.put(path.getFileName().toString().replace(".java", ""), read(path)));
        }
        List<String> orphans = java.util.Arrays.stream(com.jrobertgardzinski.security.domain.vo.StepUpAction.values())
                .filter(action -> sources.values().stream().noneMatch(source -> source.contains("StepUpAction." + action.name())))
                .map(Enum::name)
                .toList();
        assertEquals(List.of(), orphans,
                "these actions are in the catalogue but no endpoint consumes an elevation for them: " + orphans);

        List<String> unnamed = MUST_STEP_UP.keySet().stream().sorted()
                .filter(controller -> !sources.getOrDefault(controller, "").contains("StepUpAction."))
                .toList();
        assertEquals(List.of(), unnamed,
                "these endpoints step up without naming their action from the catalogue: " + unnamed);
    }

    private static String read(Path path) {
        try {
            return Files.readString(path);
        } catch (IOException unreadable) {
            throw new IllegalStateException("cannot read " + path, unreadable);
        }
    }

    private static Set<String> controllers() throws IOException {
        try (Stream<Path> files = walkAll()) {
            return files.map(Path::getFileName)
                    .map(Path::toString)
                    .filter(name -> name.endsWith("Controller.java"))
                    .map(name -> name.substring(0, name.length() - ".java".length()))
                    .collect(Collectors.toCollection(TreeSet::new));
        }
    }

    private static boolean guards(String controller) {
        try (Stream<Path> files = walkAll()) {
            Path source = files.filter(path -> path.getFileName().toString().equals(controller + ".java"))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("no such controller: " + controller));
            return Files.readString(source).contains("requireElevation");
        } catch (IOException unreadable) {
            throw new IllegalStateException("cannot read " + controller, unreadable);
        }
    }
    private static Stream<Path> walkAll() throws IOException {
        Stream<Path> all = Stream.empty();
        for (Path root : CONTROLLERS) {
            all = Stream.concat(all, Files.walk(root));
        }
        return all;
    }
}
