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
 * A law, in the spirit of ADR 0006: every store that keeps state in a map is CLASSIFIED — either
 * what it holds has a deadline and something removes it when the deadline passes, or its entries
 * live as long as the account they belong to and a timer removing them would be a bug.
 *
 * <p>P18 poz. 17 found ONE of these growing without a bound. Finding it was luck: nothing
 * distinguished it from its neighbours, and its neighbours had exactly the same shape. Asking the
 * question of every store at once turned up five more — including a table whose expiry was enforced
 * only when READING it, so the rows piled up while every decision still looked right.
 *
 * <p>The classification is the useful part, and it follows how the bean is WIRED, which the test
 * cannot check but you can read here:
 *
 * <ul>
 *   <li>{@link #PRODUCTION_WITH_A_DEADLINE} — wired UNCONDITIONALLY. These run in production, in
 *       front of endpoints a stranger can reach, and hold something that stops mattering at a known
 *       moment. An unbounded one is a defect, not untidiness: whoever can reach the endpoint decides
 *       how fast it grows.</li>
 *   <li>{@link #MIRRORS_A_REAPED_TABLE} — wired {@code @Requires(missingBeans = DataSource.class)}:
 *       the database's stand-in where none is configured. The table it mirrors has a reaper, so the
 *       twin sweeps too. Not because a dev instance will run out of memory, but because a twin that
 *       quietly behaves differently from the real thing is how a test proves something that is not
 *       true of production.</li>
 *   <li>{@link #LIVES_WITH_THE_ACCOUNT} — entries die with the account and not a moment sooner. A
 *       timer here would delete people's factors.</li>
 *   <li>{@link #CAPTURE_BUFFERS} — not stores at all: they exist so a test can assert on what would
 *       have been sent. Keeping everything IS the feature.</li>
 * </ul>
 */
class StoresWithADeadlineEvictThemTest {

    private static final List<Path> SOURCES = List.of(Path.of("src/main/java/com/jrobertgardzinski"));

    /** Wired unconditionally; holds something with a deadline. Must sweep. */
    private static final Map<String, String> PRODUCTION_WITH_A_DEADLINE = Map.of(
            "InMemorySessionElevation", "an elevation is FRESH proof — freshness is the entire point of it",
            "InMemoryStepUpStore", "a step-up challenge outlives its usefulness in minutes",
            "InMemoryPendingAuthenticationStore", "a half-finished sign-in either finishes or it does not",
            "OauthFlowStore", "anyone may start a federated sign-in and walk away — P18 poz. 17",
            "InMemoryEnrolmentChallengeStore", "the same shape as the flow store: starting an enrolment"
                    + " nobody finishes costs one request and is remembered for ever",
            "InMemorySpentTotpSteps", "a spent TOTP step stops mattering the moment it leaves the"
                    + " factor's ±1-step window — what is kept after that is a number nobody will"
                    + " ever ask about again");

    /** The database's stand-in; the table it mirrors is reaped, so this sweeps the same way. */
    private static final Map<String, String> MIRRORS_A_REAPED_TABLE = Map.of(
            "InMemoryAuthenticationBlockRepository", "ExpiredBlockReaper",
            "InMemoryRejectedAuthenticationRepository", "RejectedAuthenticationReaper",
            "InMemoryEmailChangeRepository", "AbandonedEmailChangeReaper",
            "InMemoryAuthorizationDataRepository", "ExpiredSessionReaper",
            "InMemoryAccountDeletionSagaStore", "SettledDeletionSagaReaper");

    /** Entries die with the account. Sweeping these deletes what nobody asked to delete. */
    private static final Map<String, String> LIVES_WITH_THE_ACCOUNT = Map.ofEntries(
            Map.entry("InMemoryUserRepository", "the accounts themselves"),
            Map.entry("InMemoryEnrolledFactorRepository", "a factor is enrolled until its owner removes it"),
            Map.entry("InMemoryRecoveryCodeRepository", "spare keys, minted once and kept until used"),
            Map.entry("InMemoryPasswordlessAccountRepository", "a mark on the account, not an event"),
            Map.entry("InMemoryFederatedIdentityRepository", "the link to a provider outlives every session"),
            Map.entry("InMemoryEmailVerificationRepository", "one row per address, overwritten in place"),
            Map.entry("InMemoryPasswordResetRepository", "one row per address, overwritten in place"));

    /**
     * Configuration rows: a runtime override stands until an administrator withdraws it. No
     * deadline and no reaper — on EITHER side of the DataSource switch: the table has none, so
     * its twin may not sweep either, and a timer here would silently withdraw a policy someone
     * deliberately set.
     */
    private static final Map<String, String> OPERATOR_OWNED_CONFIGURATION = Map.of(
            "InMemorySecuritySettings", "the runtime level of the configuration ladder —"
                    + " security_settings has no reaper, so neither may its twin");

    /** Assertion sinks. Keeping everything is what they are for. */
    private static final Set<String> CAPTURE_BUFFERS = Set.of(
            "CapturingEmailCodeChannel", "CapturingSmsCodeChannel", "CapturingEmailVerificationNotifier",
            "CapturingPasswordResetNotifier", "CapturingRegistrationNoticeNotifier", "InMemoryOutboxAppender");

    @Test
    void every_store_that_keeps_state_in_a_map_is_classified() throws IOException {
        Set<String> classified = new TreeSet<>(PRODUCTION_WITH_A_DEADLINE.keySet());
        classified.addAll(MIRRORS_A_REAPED_TABLE.keySet());
        classified.addAll(LIVES_WITH_THE_ACCOUNT.keySet());
        classified.addAll(OPERATOR_OWNED_CONFIGURATION.keySet());
        classified.addAll(CAPTURE_BUFFERS);

        Set<String> found = storesKeepingStateInMemory();

        Set<String> unclassified = found.stream()
                .filter(name -> !classified.contains(name))
                .collect(Collectors.toCollection(TreeSet::new));
        assertTrue(unclassified.isEmpty(),
                "a new in-memory store appeared and nobody said which kind it is: does what it holds"
                        + " have a deadline, does it mirror a reaped table, does it live with the account,"
                        + " or is it an assertion sink? " + unclassified);

        Set<String> vanished = classified.stream()
                .filter(name -> !found.contains(name))
                .collect(Collectors.toCollection(TreeSet::new));
        assertTrue(vanished.isEmpty(),
                "these are classified but no longer keep anything in a map — the list is drifting"
                        + " into fiction: " + vanished);
    }

    @Test
    void everything_with_a_deadline_actually_sweeps() throws IOException {
        List<String> unbounded = PRODUCTION_WITH_A_DEADLINE.entrySet().stream()
                .filter(entry -> !sweeps(entry.getKey()))
                .map(entry -> entry.getKey() + " (" + entry.getValue() + ")")
                .toList();

        assertEquals(List.of(), unbounded,
                "these run in production, hold entries that stop mattering, and never remove them:"
                        + " the map grows for as long as the process lives and a stranger sets the pace");
    }

    @Test
    void every_twin_of_a_reaped_table_sweeps_the_same_way() {
        List<String> drifting = MIRRORS_A_REAPED_TABLE.entrySet().stream()
                .filter(entry -> !sweeps(entry.getKey()))
                .map(entry -> entry.getKey() + " (the table is reaped by " + entry.getValue() + ")")
                .toList();

        assertEquals(List.of(), drifting,
                "the datasource-backed twin removes these rows and the in-memory one keeps them for"
                        + " ever — the two adapters no longer behave the same, which is exactly what"
                        + " tests running against the in-memory one will fail to notice");
    }

    @Test
    void the_reapers_named_here_exist() throws IOException {
        Set<String> present;
        try (Stream<Path> files = walkAll()) {
            present = files.map(path -> path.getFileName().toString())
                    .filter(name -> name.endsWith(".java"))
                    .map(name -> name.substring(0, name.length() - ".java".length()))
                    .collect(Collectors.toCollection(TreeSet::new));
        }

        List<String> missing = MIRRORS_A_REAPED_TABLE.values().stream()
                .distinct()
                .filter(reaper -> !present.contains(reaper))
                .toList();

        assertEquals(List.of(), missing,
                "this list justifies the twins by pointing at a reaper — a name here that no longer"
                        + " exists turns the justification into a story: " + missing);
    }

    @Test
    void nothing_that_lives_with_the_account_sweeps_on_a_timer() {
        List<String> swept = LIVES_WITH_THE_ACCOUNT.keySet().stream()
                .filter(StoresWithADeadlineEvictThemTest::sweeps)
                .toList();

        assertEquals(List.of(), swept,
                "a timer removing account state deletes things nobody asked to delete — if one of"
                        + " these genuinely gained a deadline, move it and say what the deadline is");
    }

    @Test
    void operator_owned_configuration_never_sweeps_on_a_timer() {
        List<String> swept = OPERATOR_OWNED_CONFIGURATION.keySet().stream()
                .filter(StoresWithADeadlineEvictThemTest::sweeps)
                .toList();

        assertEquals(List.of(), swept,
                "a timer withdrawing configuration rows silently un-decides what an administrator"
                        + " decided — an override is withdrawn by deleting the row, never by age");
    }

    private static Set<String> storesKeepingStateInMemory() throws IOException {
        try (Stream<Path> files = walkAll()) {
            return files.filter(file -> file.toString().endsWith(".java"))
                    .filter(StoresWithADeadlineEvictThemTest::keepsStateInAMap)
                    .map(file -> file.getFileName().toString())
                    .map(name -> name.substring(0, name.length() - ".java".length()))
                    .collect(Collectors.toCollection(TreeSet::new));
        }
    }

    private static boolean keepsStateInAMap(Path file) {
        String source = read(file);
        return source.contains("new ConcurrentHashMap")
                || source.contains("ConcurrentHashMap.newKeySet")
                || source.contains("new CopyOnWriteArrayList");
    }

    private static boolean sweeps(String store) {
        try (Stream<Path> files = walkAll()) {
            Path source = files.filter(path -> path.getFileName().toString().equals(store + ".java"))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("no such store: " + store));
            String text = read(source);
            // The annotation is matched WITHOUT its leading '@' on purpose: written out in full it
            // reads "@io.micronaut.scheduling.annotation.Scheduled", and a law that recognises only
            // one of the two spellings reports a store as unbounded while it sweeps every minute.
            return text.contains("Scheduled(") && text.contains("removeIf");
        } catch (IOException unreadable) {
            throw new IllegalStateException("cannot list " + SOURCES, unreadable);
        }
    }

    private static String read(Path file) {
        try {
            return Files.readString(file);
        } catch (IOException unreadable) {
            throw new IllegalStateException("cannot read " + file, unreadable);
        }
    }
    private static Stream<Path> walkAll() throws IOException {
        Stream<Path> all = Stream.empty();
        for (Path root : SOURCES) {
            all = Stream.concat(all, Files.walk(root));
        }
        return all;
    }
}
