package com.jrobertgardzinski.security.infrastructure.feature.settings;

import com.jrobertgardzinski.CapturingEmailVerificationNotifier;
import com.jrobertgardzinski.persistence.InMemorySecuritySettings;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * HTTP glue for {@code settings.feature}. Black-box: users are really registered and verified,
 * tokens are obtained by authenticating, a rule is set via PUT /admin/settings/{key} (behind a
 * step-up, like every admin hand) and the catalogue is read via GET /admin/settings.
 * "admin@example.com" is a bootstrap admin (test config). The one look behind the API is on
 * purpose: "nothing was written" is proved on the in-memory settings table itself.
 */
public class HttpSettingsSteps {

    private static final String PASSWORD = "StrongPassword1!";
    private static final String ADMIN = "admin@example.com";
    private static final String SETTINGS = "/admin/settings";

    private EmbeddedServer server;
    private BlockingHttpClient client;
    private HttpResponse<Map> response;
    /** The catalogue as last read: every live key with what is in force under it. */
    private Map<?, ?> catalogue;

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

    @When("the ADMIN SETS {string} to {string}")
    public void theAdminSets(String key, String value) {
        response = set(tokenFor(ADMIN), key, value);
    }

    @When("{string} tries to SET {string} to {string}")
    public void triesToSet(String caller, String key, String value) {
        response = set(tokenFor(caller), key, value);
    }

    @When("the ADMIN asks for the catalogue")
    public void theAdminAsksForTheCatalogue() {
        fetchCatalogue();
    }

    @Then("the setting is ACCEPTED holding {string}")
    public void theSettingIsAccepted(String value) {
        assertEquals(HttpStatus.OK, response.getStatus(), response.getBody(Map.class).map(Object::toString).orElse(""));
        Map<?, ?> body = response.getBody(Map.class).orElseThrow();
        assertEquals("ACCEPTED", body.get("status"));
        assertEquals(value, String.valueOf(body.get("value")));
    }

    @Then("the setting is REFUSED because {string}")
    public void theSettingIsRefusedBecause(String reason) {
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatus());
        Map<?, ?> body = response.getBody(Map.class).orElseThrow();
        assertEquals("REFUSED", body.get("status"));
        assertTrue(String.valueOf(body.get("reason")).startsWith(reason),
                "expected the gate's reason to start with '" + reason + "', was: " + body.get("reason"));
    }

    @Then("the setting is UNKNOWN")
    public void theSettingIsUnknown() {
        assertEquals(HttpStatus.NOT_FOUND, response.getStatus());
        assertEquals("UNKNOWN_KEY", response.getBody(Map.class).orElseThrow().get("status"));
    }

    @Then("nothing was written under {string}")
    public void nothingWasWrittenUnder(String key) {
        assertFalse(server.getApplicationContext().getBean(InMemorySecuritySettings.class).rows().containsKey(key),
                "a row was written under " + key);
    }

    @Then("{string} in force is {string}, decided by the {string} source")
    public void inForceIs(String key, String value, String source) {
        fetchCatalogue();
        Map<?, ?> entry = (Map<?, ?>) catalogue.get(key);
        assertNotNull(entry, "no such key in the catalogue: " + catalogue);
        assertEquals(value, String.valueOf(entry.get("value")));
        assertEquals(source, entry.get("source"));
    }

    @Then("the catalogue lists exactly {string}, {string}, {string}, {string} and {string}")
    public void theCatalogueListsExactly(String first, String second, String third, String fourth, String fifth) {
        assertEquals(List.of(first, second, third, fourth, fifth), List.copyOf(catalogue.keySet()));
    }

    @Then("every entry says what is in force and which source decided it")
    public void everyEntrySaysWhatIsInForce() {
        catalogue.forEach((key, entry) -> {
            Map<?, ?> report = (Map<?, ?>) entry;
            assertNotNull(report.get("value"), key + " has no value");
            assertNotNull(report.get("source"), key + " has no source");
            assertTrue(report.get("rejected") instanceof List<?>, key + " has no rejected list");
        });
    }

    @When("the USER REGISTERS with EMAIL {string} and password {string}")
    public void theUserRegisters(String email, String password) {
        response = exchange(HttpRequest.POST("/register", Map.of("email", email, "password", password)));
    }

    @Then("REGISTRATION succeeds")
    public void registrationSucceeds() {
        assertEquals(HttpStatus.CREATED, response.getStatus(), response.getBody(Map.class).map(Object::toString).orElse(""));
    }

    @Then("the request is forbidden")
    public void requestForbidden() {
        assertEquals(HttpStatus.FORBIDDEN, response.getStatus());
    }

    private void fetchCatalogue() {
        HttpResponse<Map> fetched = exchange(HttpRequest.GET(SETTINGS).header("Authorization", "Bearer " + tokenFor(ADMIN)));
        assertEquals(HttpStatus.OK, fetched.getStatus());
        catalogue = fetched.getBody(Map.class).orElseThrow();
    }

    private String tokenFor(String email) {
        HttpResponse<Map> authed = exchange(HttpRequest.POST("/authenticate", Map.of("email", email, "password", PASSWORD)));
        assertEquals(HttpStatus.OK, authed.getStatus(), "could not authenticate " + email);
        return (String) authed.getBody(Map.class).orElseThrow().get("accessToken");
    }

    private HttpResponse<Map> set(String token, String key, String value) {
        stepUp(token);
        return exchange(HttpRequest.PUT(SETTINGS + "/" + key, Map.of("value", value)).header("Authorization", "Bearer " + token));
    }

    /**
     * A rule binds every future decision under it, so setting one takes fresh proof and not
     * merely a live session. Every caller here has a password and no factors, so re-entering the
     * password elevates at once — including the caller who is then refused on their ROLE.
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
        } catch (HttpClientResponseException refused) {
            return (HttpResponse<Map>) refused.getResponse();
        }
    }
}
