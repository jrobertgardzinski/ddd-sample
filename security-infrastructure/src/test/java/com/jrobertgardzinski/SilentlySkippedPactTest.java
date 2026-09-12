package com.jrobertgardzinski;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The guard on the guards: <b>skipping a pact verification is allowed only when the consumer
 * workspace is genuinely absent.</b>
 *
 * <p>This service is the PROVIDER for two contracts — the {@code GET /me} introspection that
 * memes' authorisation gate reads, and the {@code ACCOUNT_DELETION_REQUESTED} fact offboarding
 * opens sagas on. Both provider tests carry an {@code @EnabledIf} so a lone checkout of this repo
 * does not fail a build over a directory that was never cloned. That guard is reasonable and it is
 * also exactly how both verifications died: the estate split into three workspaces on 2026-07-12,
 * the consumers moved to {@code portal/}, and the paths kept pointing at {@code shared/}. The
 * directory stopped existing, {@code @EnabledIf} did its job, and JUnit reported SKIPPED — which
 * reads green. A breaking change to the shape of {@code /me} would have passed a full
 * {@code mvn test} of this service without a single red mark, for as long as nobody looked.
 *
 * <p>So the skip needs a witness. If the consumer IS checked out and the provider test still
 * cannot find its pacts, that is a stale path rather than a lone checkout, and it fails HERE
 * instead of hiding. This class carries no {@code @EnabledIf} of its own on purpose: it has to run
 * in every layout, so that the one thing it can prove — "nothing is being skipped for the wrong
 * reason" — is proven on every run. Modelled on the test of the same name in memes.
 */
class SilentlySkippedPactTest {

    /** Relative to the MODULE directory, which is what surefire makes the working directory. */
    private static final String WORKSPACES_ROOT = "../../..";

    private record Consumer(String workspace, String repo, String pactDir, String providerTest) {

        Path consumerRoot() {
            return Path.of(WORKSPACES_ROOT, workspace, repo);
        }

        Path pacts() {
            return Path.of(WORKSPACES_ROOT, workspace, repo, pactDir);
        }
    }

    private static final List<Consumer> CONSUMERS = List.of(
            new Consumer("portal", "microservice-memes", "pacts-http", "MeIntrospectionPactProviderTest"),
            new Consumer("portal", "microservice-offboarding", "pacts", "OffboardingFactsPactProviderTest"),
            // the other two carry the SAME @EnabledIf skip and had no witness at all: both live in
            // this workspace, so "not cloned" is not an excuse either of them can honestly make
            new Consumer("shared", "microservice-email", "pacts", "MailRequestsPactProviderTest"),
            new Consumer("shared", "offline-jwt", "pacts", "JwksPactProviderTest"));

    @Test
    @DisplayName("every checked-out consumer's pacts are where its provider test looks for them")
    void a_checked_out_consumer_is_never_skipped() {
        for (Consumer consumer : CONSUMERS) {
            if (!Files.isDirectory(consumer.consumerRoot())) {
                continue;   // genuinely not cloned — the skip is honest and this test has no opinion
            }
            assertTrue(Files.isDirectory(consumer.pacts()),
                    consumer.repo() + " IS checked out, so its pacts must be readable at "
                            + consumer.pacts() + ". They are not — which means "
                            + consumer.providerTest() + " skips without verifying anything and"
                            + " reports that as success. Either the path drifted (as it did after"
                            + " the workspace split) or the consumer stopped recording the pact.");
        }
    }
}
