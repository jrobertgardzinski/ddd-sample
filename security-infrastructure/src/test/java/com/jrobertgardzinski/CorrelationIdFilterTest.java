package com.jrobertgardzinski;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.http.HttpRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The access line this filter writes for EVERY request must not carry an e-mail address (poz. 27).
 * Two admin endpoints name their subject in the path, and this log goes to Loki and stays for weeks —
 * so the assertion is on the line that is actually emitted, not on the masking function alone.
 */
class CorrelationIdFilterTest {

    private final Logger logger = (Logger) LoggerFactory.getLogger(CorrelationIdFilter.class);
    private final ListAppender<ILoggingEvent> captured = new ListAppender<>();

    @BeforeEach
    void attachAppender() {
        captured.start();
        logger.addAppender(captured);
    }

    @AfterEach
    void detachAppender() {
        logger.detachAppender(captured);
        captured.stop();
    }

    @Test
    @DisplayName("the address in an admin path never reaches the access log")
    void admin_paths_are_logged_without_the_address() {
        new CorrelationIdFilter().onRequest(
                HttpRequest.PUT("/admin/users/victim@example.com/roles", Map.of("roles", "MODERATOR")));

        String line = onlyLine();
        assertFalse(line.contains("victim@example.com"), "the address reached the access log: " + line);
        assertTrue(line.contains("vi***@example.com"), "the line must still identify the subject: " + line);
        assertTrue(line.contains("/admin/users/") && line.contains("/roles"),
                "the route must stay readable, that is what the line is for: " + line);
    }

    @Test
    @DisplayName("an ordinary path is logged exactly as it arrived")
    void ordinary_paths_are_untouched() {
        new CorrelationIdFilter().onRequest(HttpRequest.DELETE("/account/leaver@example.com", Map.of()));

        // the address in the path is masked on the way into the log (MaskedEmail.maskedPath)
        assertTrue(onlyLine().contains("/account/le***@example.com"), onlyLine());
    }

    private String onlyLine() {
        return captured.list.stream()
                .map(ILoggingEvent::getFormattedMessage)
                .reduce((a, b) -> a + " | " + b)
                .orElseThrow(() -> new AssertionError("the filter logged no access line at all"));
    }

    @Test
    @DisplayName("an inbound correlation id is kept only while it is one: short, and id-shaped")
    void a_caller_cannot_write_its_own_essay_into_every_log_line() {
        String essay = "x".repeat(4096);
        new CorrelationIdFilter().onRequest(
                HttpRequest.GET("/me").header(CorrelationIdFilter.HEADER, essay));

        String line = onlyLine();
        assertFalse(line.contains(essay),
                "this id is echoed and logged on every line of the request — unbounded, it is a"
                        + " kilobyte of somebody else's text in every aggregator the estate has");
        assertTrue(line.startsWith("cid=") && line.length() < 200, line);
    }

    @Test
    @DisplayName("an ordinary inbound id is honoured, because following one request across services is the point")
    void a_real_correlation_id_is_kept() {
        new CorrelationIdFilter().onRequest(
                HttpRequest.GET("/me").header(CorrelationIdFilter.HEADER, "portal-7f3a9c2e"));

        assertTrue(onlyLine().contains("portal-7f3a9c2e"), onlyLine());
    }
}
