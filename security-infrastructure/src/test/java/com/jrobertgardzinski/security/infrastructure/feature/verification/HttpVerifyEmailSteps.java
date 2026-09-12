package com.jrobertgardzinski.security.infrastructure.feature.verification;

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

/**
 * HTTP glue for {@code verify-email.feature}. Black-box: request verification, read back the token
 * the app would have e-mailed (via the test notifier), then confirm it — and confirm that a garbage
 * token is refused.
 */
public class HttpVerifyEmailSteps {

    private EmbeddedServer server;
    private BlockingHttpClient client;

    private String email;
    private String password;
    private String linkToken;
    private String tokenBeforeTheRequest;
    private HttpResponse<Map> response;

    @Before
    public void startServer() {
        server = ApplicationContext.run(EmbeddedServer.class);
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
        this.password = password;
        HttpResponse<Map> seeded = exchange(HttpRequest.POST("/register", Map.of("email", email, "password", password)));
        assertEquals(HttpStatus.CREATED, seeded.getStatus(), "failed to seed the user");
    }

    /**
     * At this layer registering IS the unverified state — the link is mailed and nothing has been
     * followed yet. The wording exists because the browser harness's "a registered USER" completes
     * onboarding, and a scenario that needs an unverified address must say so in one place.
     */
    @Given("a registered USER {string} with password {string} whose EMAIL is not verified yet")
    public void aRegisteredUnverifiedUser(String email, String password) {
        aRegisteredUser(email, password);
    }

    @Given("the USER has VERIFIED the EMAIL")
    public void theUserHasVerifiedTheEmail() {
        theUserRequestedEmailVerification();
        HttpResponse<Map> verified = exchange(HttpRequest.POST("/verify-email", Map.of("token", linkToken)));
        assertEquals(HttpStatus.OK, verified.getStatus(), "failed to seed a verified address");
    }

    @When("EMAIL VERIFICATION is requested again for that EMAIL")
    public void verificationIsRequestedAgain() {
        tokenBeforeTheRequest = mailedToken();
        response = exchange(HttpRequest.POST("/verify-email/request", Map.of("email", email)));
    }

    @Then("the request is accepted as quietly as any other")
    public void theRequestIsAcceptedQuietly() {
        assertEquals(HttpStatus.ACCEPTED, response.getStatus());
        assertEquals("VERIFICATION_LINK_SENT", response.getBody(Map.class).orElseThrow().get("status"));
    }

    @Then("the EMAIL is still verified")
    public void theEmailIsStillVerified() {
        // the proof that matters to the owner: signing in still works. Sign-in is the only place
        // the verified flag is felt, and flipping it is exactly how this endpoint was abusable.
        HttpResponse<Map> authenticated =
                exchange(HttpRequest.POST("/authenticate", Map.of("email", email, "password", password)));
        assertEquals(HttpStatus.OK, authenticated.getStatus(),
                "the owner must still be able to sign in: " + authenticated.getBody(Map.class).orElse(Map.of()));
    }

    @Then("no new VERIFICATION link was e-mailed")
    public void noNewLinkWasEmailed() {
        assertEquals(tokenBeforeTheRequest, mailedToken(),
                "a fresh token means the address was reset to unverified");
    }

    @Given("the USER requested EMAIL VERIFICATION")
    public void theUserRequestedEmailVerification() {
        HttpResponse<Map> requested = exchange(HttpRequest.POST("/verify-email/request", Map.of("email", email)));
        assertEquals(HttpStatus.ACCEPTED, requested.getStatus());
        linkToken = server.getApplicationContext()
                .getBean(CapturingEmailVerificationNotifier.class).lastTokenFor(email);
        assertNotNull(linkToken, "no verification token was e-mailed");
    }

    @When("the USER VERIFIES the EMAIL with the VERIFICATION TOKEN from the link")
    public void verifiesWithTheLinkToken() {
        response = exchange(HttpRequest.POST("/verify-email", Map.of("token", linkToken)));
    }

    @When("the USER VERIFIES the EMAIL with a garbage VERIFICATION TOKEN")
    public void verifiesWithGarbageToken() {
        response = exchange(HttpRequest.POST("/verify-email", Map.of("token", "garbage-token")));
    }

    @Then("the EMAIL is verified")
    public void theEmailIsVerified() {
        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals("EMAIL_VERIFIED", response.getBody(Map.class).orElseThrow().get("status"));
    }

    @Then("the VERIFICATION is rejected")
    public void theVerificationIsRejected() {
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatus());
    }

    @Then("a VERIFICATION link has been e-mailed to the USER")
    public void aVerificationLinkHasBeenEmailed() {
        assertNotNull(mailedToken(), "expected registration to e-mail a verification link automatically");
    }

    /** The last token the app would have e-mailed to this address, or null if it never did. */
    private String mailedToken() {
        return server.getApplicationContext()
                .getBean(CapturingEmailVerificationNotifier.class).lastTokenFor(email);
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<Map> exchange(HttpRequest<?> request) {
        try {
            return client.exchange(request, Map.class);
        } catch (HttpClientResponseException e) {
            return (HttpResponse<Map>) e.getResponse();
        }
    }
}
