package com.jrobertgardzinski.security.infrastructure.feature.emailchange;

import com.jrobertgardzinski.CapturingEmailVerificationNotifier;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * HTTP glue for {@code change-email.feature}. Black-box: authenticate, request the change, read back
 * the token e-mailed to the new address (via the test notifier), confirm it, then show the user
 * authenticates under the new address and no longer under the old one.
 */
public class HttpChangeEmailSteps {

    private static final String PASSWORD = "StrongPassword1!";

    private EmbeddedServer server;
    private BlockingHttpClient client;

    private String email;
    private String accessToken;
    private String newEmail;
    private HttpResponse<Map> requestResponse;
    /** What the target address had been mailed BEFORE the change was asked for (it may be seeded). */
    private String targetTokenBefore;
    private HttpResponse<Map> confirmResponse;

    @Before
    public void startServer() {
        // this deployment refuses disposable domains — the rule the policy example is about; every
        // other address in the feature is @example.com and untouched by it
        server = ApplicationContext.run(EmbeddedServer.class,
                Map.of("security.email.disposable.domains", "mailinator.com"));
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
        this.email = email;
        HttpResponse<Map> seeded = exchange(HttpRequest.POST("/register", Map.of("email", email, "password", password)));
        assertEquals(HttpStatus.CREATED, seeded.getStatus(), "failed to seed the user");
        verifySeededUser(email);
    }

    @Given("the USER has AUTHENTICATED")
    public void theUserHasAuthenticated() {
        HttpResponse<Map> authenticated = authenticate(email);
        assertEquals(HttpStatus.OK, authenticated.getStatus());
        accessToken = (String) authenticated.getBody(Map.class).orElseThrow().get("accessToken");
    }

    @Given("another ACCOUNT already holds {string}")
    public void anotherAccountAlreadyHolds(String takenEmail) {
        HttpResponse<Map> seeded = exchange(
                HttpRequest.POST("/register", Map.of("email", takenEmail, "password", PASSWORD)));
        assertEquals(HttpStatus.CREATED, seeded.getStatus(), "failed to seed the occupying account");
    }

    @When("the USER requests to CHANGE the EMAIL to {string}")
    public void theUserRequestsToChangeTheEmail(String newEmail) {
        this.newEmail = newEmail;
        this.targetTokenBefore = mailedTokenFor(newEmail);
        stepUpForTheChange();
        requestResponse = exchange(HttpRequest.POST("/account/email/request", Map.of("newEmail", newEmail))
                .header("Authorization", "Bearer " + accessToken));
        assertEquals(HttpStatus.ACCEPTED, requestResponse.getStatus());
    }

    /**
     * Moving the address moves the account, and the confirmation lands in the NEW mailbox — so a
     * live session alone is not enough to start one. This user has a password and no factors, so
     * re-entering the password elevates the session at once.
     */
    private void stepUpForTheChange() {
        HttpResponse<Map> elevated = exchange(HttpRequest.POST("/account/step-up",
                        Map.of("action", "change-email", "password", PASSWORD))
                .header("Authorization", "Bearer " + accessToken));
        assertEquals(HttpStatus.OK, elevated.getStatus());
        assertEquals("ELEVATED", elevated.getBody(Map.class).orElseThrow().get("status"));
    }

    /** Same call as the step above, but with no verdict assumed: this one is expected to be refused. */
    @When("the USER tries to CHANGE the EMAIL to {string}")
    public void theUserTriesToChangeTheEmail(String newEmail) {
        this.newEmail = newEmail;
        stepUpForTheChange();
        requestResponse = exchange(HttpRequest.POST("/account/email/request", Map.of("newEmail", newEmail))
                .header("Authorization", "Bearer " + accessToken));
    }

    @Then("the CHANGE is refused because the domain is DISPOSABLE")
    public void refusedAsDisposable() {
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, requestResponse.getStatus());
        assertTrue(String.valueOf(requestResponse.getBody(Map.class).orElseThrow().get("emailErrors"))
                        .contains("DISPOSABLE_DOMAIN"),
                "the refusal must name the broken rule, the same shape /register answers with");
        assertNull(server.getApplicationContext().getBean(CapturingEmailVerificationNotifier.class)
                        .lastTokenFor(newEmail),
                "no link may be sent to an address the deployment does not admit");
    }

    @When("the USER CONFIRMS the EMAIL CHANGE with the token from the link")
    public void confirmsWithTheLinkToken() {
        String linkToken = server.getApplicationContext()
                .getBean(CapturingEmailVerificationNotifier.class).lastTokenFor(newEmail);
        assertNotNull(linkToken, "no verification token was e-mailed to the new address");
        confirmResponse = exchange(HttpRequest.POST("/confirm-email-change", Map.of("token", linkToken)));
    }

    @Then("the CHANGE request is quietly refused, indistinguishable from a fresh one")
    public void quietlyRefused() {
        assertEquals(HttpStatus.ACCEPTED, requestResponse.getStatus());
        // "indistinguishable" is about the WIRE; the address itself must not be touched. Nothing
        // asserted that until 2026-09-12, so a quiet 202 that had nevertheless started a change —
        // mailing the occupant a confirmation link for somebody else's move — would have passed.
        // The comparison is against what that address had been sent BEFORE (it was seeded by a
        // registration of its own), because "no NEW link" is the claim, not "no link ever".
        assertEquals(targetTokenBefore, mailedTokenFor(newEmail),
                "no change link may go to an address that belongs to somebody else");
        assertEquals(Map.of("status", "EMAIL_CHANGE_LINK_SENT"), requestResponse.getBody(Map.class).orElseThrow(),
                "a taken address must answer byte-for-byte like a fresh change request");
    }

    @Then("the owner of {string} is notified by mail")
    public void ownerIsNotified(String takenEmail) {
        org.junit.jupiter.api.Assertions.assertTrue(server.getApplicationContext()
                        .getBean(com.jrobertgardzinski.CapturingRegistrationNoticeNotifier.class)
                        .noticedEmails().contains(takenEmail),
                "the taken address's owner learns someone tried to use it");
    }

    @When("the USER CONFIRMS the EMAIL CHANGE with a garbage token")
    public void confirmsWithGarbageToken() {
        confirmResponse = exchange(HttpRequest.POST("/confirm-email-change", Map.of("token", "garbage-token")));
    }

    @Given("the USER also signs in through {string} as subject {string}")
    public void alsoSignsInThrough(String provider, String subject) {
        federatedIdentities().link(provider, subject, com.jrobertgardzinski.email.domain.Email.of(email));
    }

    @Then("the {string} identity {string} opens the account {string}")
    public void identityOpensTheAccount(String provider, String subject, String email) {
        org.junit.jupiter.api.Assertions.assertEquals(email,
                federatedIdentities().findUserBy(provider, subject)
                        .map(com.jrobertgardzinski.email.domain.Email::value).orElse(null),
                "the federated link follows the account — the subject is the person, not the address");
    }

    private com.jrobertgardzinski.security.domain.repository.FederatedIdentityRepository federatedIdentities() {
        return server.getApplicationContext()
                .getBean(com.jrobertgardzinski.security.domain.repository.FederatedIdentityRepository.class);
    }

    @Then("the USER can AUTHENTICATE as {string}")
    public void canAuthenticateAs(String asEmail) {
        assertEquals(HttpStatus.OK, authenticate(asEmail).getStatus());
    }

    @Then("the USER cannot AUTHENTICATE as {string}")
    public void cannotAuthenticateAs(String asEmail) {
        assertEquals(HttpStatus.UNAUTHORIZED, authenticate(asEmail).getStatus());
    }

    @Then("the SESSION held since before the CHANGE no longer authorizes")
    public void theOldSessionNoLongerAuthorizes() {
        // the token is the one minted under the old address; it must not speak for the account any
        // more — nor, once the freed address is registered again, for its next owner
        HttpResponse<Map> me = exchange(HttpRequest.GET("/me").header("Authorization", "Bearer " + accessToken));
        assertEquals(HttpStatus.UNAUTHORIZED, me.getStatus(),
                "a session minted before the move still authorizes: " + me.getBody(Map.class).orElse(Map.of()));
    }

    @Then("the EMAIL CHANGE is rejected")
    public void theEmailChangeIsRejected() {
        assertEquals(HttpStatus.BAD_REQUEST, confirmResponse.getStatus());
    }

    private HttpResponse<Map> authenticate(String asEmail) {
        return exchange(HttpRequest.POST("/authenticate", Map.of("email", asEmail, "password", PASSWORD)));
    }

    /** The last verification token this address was mailed, or null if it never was. */
    private String mailedTokenFor(String address) {
        return server.getApplicationContext()
                .getBean(CapturingEmailVerificationNotifier.class).lastTokenFor(address);
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
