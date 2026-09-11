package com.jrobertgardzinski.security.infrastructure.feature.deleteaccount;

import com.jrobertgardzinski.AccountDeletionOrchestrator;
import com.jrobertgardzinski.CapturingEmailVerificationNotifier;
import com.jrobertgardzinski.persistence.InMemoryOutboxAppender;
import io.cucumber.java.After;
import io.cucumber.java.Before;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import io.micronaut.context.ApplicationContext;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * HTTP glue for {@code delete-account.feature}. The saga's edges that need other services are
 * driven through the orchestrator bean — the same code path the Kafka listener calls — while
 * everything else stays black-box HTTP; the full loop over a real broker runs in the workspace's
 * compose smoke test. Time is steered through the test clock endpoint, so "overdue" is exact.
 */
public class HttpDeleteAccountSteps {

    private EmbeddedServer server;
    private BlockingHttpClient client;

    private static final String ADMIN = "admin@example.com";

    private String email;
    private String accessToken;
    /** The last admin-route response, for the scenarios that assert on its status alone. */
    private HttpResponse<Map> adminResponse;

    @Before
    public void startServer() {
        // The safety net is pinned SMALL for this context on purpose. The scenario is about the
        // rule ("silence past the limit rolls the closure back"), not about what the limit is —
        // and while it hard-coded a jump past the production default, every change to that default
        // broke it (12m arrived and a 6-minute jump stopped being past anything). Two minutes here
        // means the step advances three and the scenario stops caring what production runs.
        server = ApplicationContext.run(EmbeddedServer.class,
                Map.of("account-deletion.purge-timeout", "2m"));
        client = server.getApplicationContext()
                .createBean(HttpClient.class, server.getURL())
                .toBlocking();
    }

    @After
    public void stopServer() {
        if (server != null) {
            server.close();
        }
    }

    @Given("a registered USER {string} with password {string}")
    public void aRegisteredUser(String email, String password) {
        // the first one registered is "the USER" every later step talks about; the background also
        // seeds the administrator, and adopting THAT address would point every step at the wrong person
        if (this.email == null) {
            this.email = email;
        }
        HttpResponse<Map> seeded = exchange(HttpRequest.POST("/register", Map.of("email", email, "password", password)));
        assertEquals(HttpStatus.CREATED, seeded.getStatus(), "failed to seed the user");
        verifySeededUser(email);
    }

    @Given("the USER has AUTHENTICATED")
    public void theUserHasAuthenticated() {
        HttpResponse<Map> authenticated = authenticate("StrongPassword1!");
        assertEquals(HttpStatus.OK, authenticated.getStatus());
        accessToken = (String) authenticated.getBody(Map.class).orElseThrow().get("accessToken");
    }

    @When("the USER requests account DELETION")
    public void theUserRequestsAccountDeletion() {
        stepUpForDeletion();
        HttpResponse<Map> closed = exchange(HttpRequest.DELETE("/account/" + email, null)
                .header("Authorization", "Bearer " + accessToken));
        assertEquals(HttpStatus.ACCEPTED, closed.getStatus());
    }

    @Given("the USER requested account DELETION")
    public void theUserRequestedAccountDeletion() {
        theUserRequestsAccountDeletion();
    }

    @When("the ADMIN CLOSES {string} keeping content with at least {int} votes")
    public void adminClosesKeepingPopularContent(String target, int minScore) {
        String rule = "KEEP_POPULAR_ANONYMIZED:" + minScore;
        adminResponse = closeAsAdmin(tokenFor(ADMIN), target,
                Map.of("purge", Map.of("memes", rule, "comments", rule)));
    }

    @When("{string} tries to CLOSE {string}")
    public void triesToClose(String caller, String target) {
        adminResponse = closeAsAdmin(tokenFor(caller), target, null);
    }

    @Then("the request is forbidden")
    public void theRequestIsForbidden() {
        assertEquals(HttpStatus.FORBIDDEN, adminResponse.getStatus());
    }

    @Then("the request is not found")
    public void theRequestIsNotFound() {
        assertEquals(HttpStatus.NOT_FOUND, adminResponse.getStatus());
    }

    @Then("the announced deletion says the USER asked for it")
    public void theAnnouncedDeletionSaysTheUserAskedForIt() {
        assertTrue(announcedFact().contains("\"initiatedBy\":\"SELF\""),
                "expected a self-requested closure in the announced fact, got: " + announcedFact());
    }

    @Then("the announced deletion says an ADMIN asked for it")
    public void theAnnouncedDeletionSaysAnAdminAskedForIt() {
        assertTrue(announcedFact().contains("\"initiatedBy\":\"ADMIN\""),
                "expected an administrator's closure in the announced fact, got: " + announcedFact());
    }

    @When("the USER requests account DELETION spelling their address differently")
    public void theUserRequestsDeletionWithADifferentSpelling() {
        stepUpForDeletion();
        // the DOMAIN shouted, which is the same account by the rule this estate already has
        // (DomainPart lowercases; the local part stays case-sensitive, as the RFC has it). It must
        // still be read as the owner's own request, and everything downstream must address the
        // user by the exact string the account is stored under
        int at = email.indexOf('@');
        String shouted = email.substring(0, at) + "@" + email.substring(at + 1).toUpperCase();
        HttpResponse<Map> closed = exchange(HttpRequest.DELETE("/account/" + shouted, null)
                .header("Authorization", "Bearer " + accessToken));
        assertEquals(HttpStatus.ACCEPTED, closed.getStatus());
    }

    @Then("the announced deletion carries no conditions")
    public void theAnnouncedDeletionCarriesNoConditions() {
        assertFalse(announcedFact().contains("policy"),
                "a self-requested closure must state no conditions, got: " + announcedFact());
    }

    /**
     * The SAME route the person's own closure walks — only the address in it belongs to somebody
     * else, which is what turns it into an administrator's act: the ADMIN role on top of the
     * step-up. Every caller here has a password and no factors, so re-entering the password
     * elevates at once, including the caller who is then refused on their ROLE.
     */
    private HttpResponse<Map> closeAsAdmin(String token, String target, Map<String, ?> body) {
        HttpResponse<Map> elevated = exchange(HttpRequest.POST("/account/step-up",
                        Map.of("action", "admin-delete-account", "password", "StrongPassword1!"))
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.OK, elevated.getStatus());
        return exchange(HttpRequest.DELETE("/account/" + target, body)
                .header("Authorization", "Bearer " + token));
    }

    private String tokenFor(String who) {
        HttpResponse<Map> authed = exchange(HttpRequest.POST("/authenticate",
                Map.of("email", who, "password", "StrongPassword1!")));
        assertEquals(HttpStatus.OK, authed.getStatus(), "could not authenticate " + who);
        return (String) authed.getBody(Map.class).orElseThrow().get("accessToken");
    }

    /** Deleting is FULL_CHAIN step-up: this user has a password and no factors, so re-entering the
     *  password elevates the session at once. */
    private void stepUpForDeletion() {
        HttpResponse<Map> elevated = exchange(HttpRequest.POST("/account/step-up",
                        Map.of("action", "delete-account", "password", "StrongPassword1!"))
                .header("Authorization", "Bearer " + accessToken));
        assertEquals(HttpStatus.OK, elevated.getStatus());
        assertEquals("ELEVATED", elevated.getBody(Map.class).orElseThrow().get("status"));
    }

    @Then("the announced deletion carries that choice")
    public void theAnnouncedDeletionCarriesTheChoice() {
        assertTrue(announcedFact().contains("KEEP_POPULAR_ANONYMIZED:100"),
                "expected the administrator's choice in the announced fact, got: " + announcedFact());
    }

    /** The last deletion fact announced for THE USER — the payload as it will reach the portal. */
    private String announcedFact() {
        InMemoryOutboxAppender outbox = server.getApplicationContext().getBean(InMemoryOutboxAppender.class);
        return outbox.appended().stream()
                .filter(event -> event.topic().equals("security-events") && event.key().equals(email))
                .reduce((first, second) -> second)
                .orElseThrow(() -> new AssertionError("no deletion fact in the outbox"))
                .payload();
    }

    @When("the portal confirms the content purge")
    public void thePortalConfirmsTheContentPurge() {
        // the orchestrator method the Kafka listener calls on a PORTAL_CONTENT_PURGED outcome
        server.getApplicationContext().getBean(AccountDeletionOrchestrator.class).completePurge(email);
    }

    @When("the portal reports the content purge failed")
    public void thePortalReportsTheContentPurgeFailed() {
        // ...and on a PORTAL_PURGE_FAILED outcome
        server.getApplicationContext().getBean(AccountDeletionOrchestrator.class).compensate(email);
    }

    @When("no portal outcome arrives within the time limit")
    public void noPortalOutcomeArrivesInTime() {
        // past the two minutes this context pins (see startServer) — not past production's 12m
        client.exchange(HttpRequest.POST("/test/clock/advance", Map.of("duration", "PT3M")));
        server.getApplicationContext().getBean(AccountDeletionOrchestrator.class).compensateOverdue();
    }

    @Then("the email is not yet free to REGISTER")
    public void theEmailIsNotYetFree() {
        // the wire is quiet on purpose (anti-enumeration): a taken email answers 201 like a fresh
        // one — what proves the account still exists is the already-registered notice mailed to it
        int noticesBefore = noticeMails().noticedEmails().size();
        HttpResponse<Map> quiet = exchange(
                HttpRequest.POST("/register", Map.of("email", email, "password", "StrongPassword1!")));
        assertEquals(HttpStatus.CREATED, quiet.getStatus());
        assertEquals(noticesBefore + 1, noticeMails().noticedEmails().size(),
                "a taken email gets the already-registered notice, not a new account");
    }

    @Then("the USER can AUTHENTICATE again with {string}")
    public void canAuthenticateAgainWith(String password) {
        assertEquals(HttpStatus.OK, authenticate(password).getStatus());
    }

    @Then("the access token no longer authorizes")
    public void theAccessTokenNoLongerAuthorizes() {
        HttpResponse<Map> me = exchange(HttpRequest.GET("/me").header("Authorization", "Bearer " + accessToken));
        assertEquals(HttpStatus.UNAUTHORIZED, me.getStatus());
    }

    @Then("the USER cannot AUTHENTICATE with {string}")
    public void cannotAuthenticateWith(String password) {
        assertEquals(HttpStatus.UNAUTHORIZED, authenticate(password).getStatus());
    }

    @Then("the USER can REGISTER again with {string}")
    public void canRegisterAgainWith(String password) {
        // 201 alone proves nothing now (a taken email answers the same); a fresh account is told
        // apart by its side effect — a NEW verification link. The old account was verified, so a
        // still-taken email would mail a notice instead of a link.
        String tokenBefore = verificationMails().lastTokenFor(email);
        HttpResponse<Map> registered = exchange(HttpRequest.POST("/register", Map.of("email", email, "password", password)));
        assertEquals(HttpStatus.CREATED, registered.getStatus());
        org.junit.jupiter.api.Assertions.assertNotEquals(tokenBefore, verificationMails().lastTokenFor(email),
                "a freed email starts a brand-new verification");
    }

    private CapturingEmailVerificationNotifier verificationMails() {
        return server.getApplicationContext().getBean(CapturingEmailVerificationNotifier.class);
    }

    private com.jrobertgardzinski.CapturingRegistrationNoticeNotifier noticeMails() {
        return server.getApplicationContext().getBean(com.jrobertgardzinski.CapturingRegistrationNoticeNotifier.class);
    }

    private HttpResponse<Map> authenticate(String password) {
        return exchange(HttpRequest.POST("/authenticate", Map.of("email", email, "password", password)));
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<Map> exchange(HttpRequest<?> request) {
        try {
            return client.exchange(request, Map.class);
        } catch (HttpClientResponseException e) {
            return (HttpResponse<Map>) e.getResponse();
        }
    }

    private void verifySeededUser(String email) {
        // sign-in requires a verified address, so seeding completes onboarding with the e-mailed token
        String token = server.getApplicationContext()
                .getBean(CapturingEmailVerificationNotifier.class).lastTokenFor(email);
        assertNotNull(token, "no verification link was e-mailed on registration");
        HttpResponse<Map> verified = exchange(HttpRequest.POST("/verify-email", Map.of("token", token)));
        assertEquals(HttpStatus.OK, verified.getStatus(), "failed to verify the seeded user");
    }
}
