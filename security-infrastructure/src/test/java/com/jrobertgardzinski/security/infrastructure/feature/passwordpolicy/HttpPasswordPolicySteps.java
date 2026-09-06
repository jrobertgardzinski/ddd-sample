package com.jrobertgardzinski.security.infrastructure.feature.passwordpolicy;

import com.jrobertgardzinski.CapturingEmailVerificationNotifier;
import com.jrobertgardzinski.persistence.InMemorySecuritySettings;
import com.jrobertgardzinski.security.system.passwordpolicy.SetMinPasswordLength;
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

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * HTTP glue for {@code password-policy.feature}. Black-box: users are really registered and
 * verified, tokens are obtained by authenticating, the length is set via
 * POST /admin/settings/password/min-length (behind a step-up, like every admin hand) and the
 * whole policy in force is read back via GET /admin/settings/password. "admin@example.com" is a bootstrap admin (test config). The one thing done behind the
 * API's back is done on purpose: "written at the console" seeds the in-memory settings table
 * directly, bypassing the value object — which is exactly what a hand at psql does. The test
 * deployment's snapshot TTL is zero, so the table is read on every question.
 */
public class HttpPasswordPolicySteps {

    private static final String PASSWORD = "StrongPassword1!";
    private static final String ADMIN = "admin@example.com";
    private static final String POLICY = "/admin/settings/password";
    private static final String PATH = POLICY + "/min-length";

    private EmbeddedServer server;
    private BlockingHttpClient client;
    private HttpResponse<Map> response;
    /** The whole policy in force, every rule under its key. */
    private Map<?, ?> policy;

    @Before
    public void startServer() {
        server = ApplicationContext.run(EmbeddedServer.class);
        client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();
    }

    @After
    public void stopServer() {
        if (server != null) {
            server.close();
        }
    }

    @Given("a registered USER {string} with password {string}")
    public void aRegisteredUser(String email, String password) {
        HttpResponse<Map> seeded = exchange(HttpRequest.POST("/register", Map.of("email", email, "password", password)));
        assertEquals(HttpStatus.CREATED, seeded.getStatus(), "failed to seed the user");
        String token = server.getApplicationContext()
                .getBean(CapturingEmailVerificationNotifier.class).lastTokenFor(email);
        assertNotNull(token, "no verification link was e-mailed on registration");
        assertEquals(HttpStatus.OK, exchange(HttpRequest.POST("/verify-email", Map.of("token", token))).getStatus());
    }

    @Given("the ADMIN has SET the minimum password length to {int}")
    public void theAdminHasSet(int length) {
        response = set(tokenFor(ADMIN), length);
        assertEquals(HttpStatus.OK, response.getStatus(), "the precondition itself was refused");
    }

    @Given("the database row for the minimum password length holds {int}, written at the console")
    public void theDatabaseRowHoldsWrittenAtTheConsole(int value) {
        server.getApplicationContext().getBean(InMemorySecuritySettings.class).put(SetMinPasswordLength.KEY, Integer.toString(value));
    }

    @When("the ADMIN SETS the minimum password length to {int}")
    public void theAdminSets(int length) {
        response = set(tokenFor(ADMIN), length);
    }

    @When("{string} tries to SET the minimum password length to {int}")
    public void triesToSet(String caller, int length) {
        response = set(tokenFor(caller), length);
    }

    @Given("the database row {string} holds {string}, written at the console")
    public void theDatabaseRowHoldsTextWrittenAtTheConsole(String name, String value) {
        server.getApplicationContext().getBean(InMemorySecuritySettings.class).put(name, value);
    }

    @When("the ADMIN asks for the password policy in force")
    public void theAdminAsks() {
        fetchReport();
    }

    @Then("REGISTRATION succeeds")
    public void registrationSucceeds() {
        assertEquals(HttpStatus.CREATED, response.getStatus(), response.getBody(Map.class).map(Object::toString).orElse(""));
    }

    @Then("the rule {string} in force is {string}, decided by the {string} source")
    public void theRuleInForceIs(String key, String value, String source) {
        fetchReport();
        Map<?, ?> rule = (Map<?, ?>) policy.get(key);
        assertNotNull(rule, "no such rule in the report: " + policy);
        assertEquals(value, String.valueOf(rule.get("value")));
        assertEquals(source, rule.get("source"));
    }

    @Then("the report says the rule {string} was refused holding the text {string}")
    public void theReportSaysTheRuleWasRefusedHoldingTheText(String key, String held) {
        Map<?, ?> rule = (Map<?, ?>) policy.get(key);
        Object rejected = rule.get("rejected");
        assertTrue(rejected instanceof List<?> list && list.stream()
                        .anyMatch(r -> r instanceof Map<?, ?> m && held.equals(m.get("value"))),
                "expected a refusal holding " + held + " in " + rejected);
    }

    @When("the USER REGISTERS with EMAIL {string} and password {string}")
    public void theUserRegisters(String email, String password) {
        response = exchange(HttpRequest.POST("/register", Map.of("email", email, "password", password)));
    }

    @Then("REGISTRATION is rejected")
    public void registrationIsRejected() {
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, response.getStatus());
    }

    @Then("the password is flagged as {word}")
    public void thePasswordIsFlaggedAs(String flag) {
        assertTrue(passwordErrors().stream().anyMatch(error -> error.containsKey(flag)),
                "expected password error " + flag + " in " + passwordErrors());
    }

    @Then("the refusal names the minimum length in force, {int}")
    public void theRefusalNamesTheMinimumLength(int minLength) {
        assertTrue(passwordErrors().contains(Map.of("MIN_LENGTH_NOT_MET", minLength)),
                "expected {MIN_LENGTH_NOT_MET: " + minLength + "} in " + passwordErrors());
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> passwordErrors() {
        return (List<Map<String, Object>>) response.getBody(Map.class).orElseThrow().get("passwordErrors");
    }

    @Then("the minimum password length in force is {int}, decided by the {string} source")
    public void theMinimumPasswordLengthInForceIs(int value, String source) {
        fetchReport();
        assertEquals(value, minLength().get("value"));
        assertEquals(source, minLength().get("source"));
    }

    @Then("the report says the {string} source was refused holding {int} because {string}")
    public void theReportSaysTheSourceWasRefused(String source, int held, String reason) {
        Object rejected = minLength().get("rejected");
        assertTrue(rejected instanceof List<?> list
                        && list.contains(Map.of("source", source, "value", held, "reason", reason)),
                "expected the refusal in " + rejected);
    }

    @Then("the request is refused because {string}")
    public void theRequestIsRefusedBecause(String reason) {
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatus());
        assertEquals(reason, response.getBody(Map.class).orElseThrow().get("reason"));
    }

    @Then("the request is forbidden")
    public void requestForbidden() {
        assertEquals(HttpStatus.FORBIDDEN, response.getStatus());
    }

    private void fetchReport() {
        HttpResponse<Map> fetched = exchange(HttpRequest.GET(POLICY).header("Authorization", "Bearer " + tokenFor(ADMIN)));
        assertEquals(HttpStatus.OK, fetched.getStatus());
        policy = fetched.getBody(Map.class).orElseThrow();
    }

    private Map<?, ?> minLength() {
        return (Map<?, ?>) policy.get(SetMinPasswordLength.KEY);
    }

    private String tokenFor(String email) {
        HttpResponse<Map> authed = exchange(HttpRequest.POST("/authenticate", Map.of("email", email, "password", PASSWORD)));
        assertEquals(HttpStatus.OK, authed.getStatus(), "could not authenticate " + email);
        return (String) authed.getBody(Map.class).orElseThrow().get("accessToken");
    }

    private HttpResponse<Map> set(String token, int length) {
        stepUp(token);
        return exchange(HttpRequest.POST(PATH, Map.of("value", length)).header("Authorization", "Bearer " + token));
    }

    /**
     * The policy binds every future password, so setting it takes fresh proof and not merely a
     * live session. Every caller here has a password and no factors, so re-entering the password
     * elevates at once — including the caller who is then refused on their ROLE.
     */
    private void stepUp(String token) {
        HttpResponse<Map> elevated = exchange(HttpRequest.POST("/account/step-up",
                        Map.of("action", "admin-settings", "password", PASSWORD))
                .header("Authorization", "Bearer " + token));
        assertEquals(HttpStatus.OK, elevated.getStatus());
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
