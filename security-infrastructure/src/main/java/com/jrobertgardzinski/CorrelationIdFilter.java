package com.jrobertgardzinski;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.annotation.ResponseFilter;
import io.micronaut.http.annotation.ServerFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.UUID;

/**
 * Correlation id for tracing a request across services. Reads the inbound {@code X-Correlation-Id}
 * (or mints one) so a call arriving from another service (a gate checking {@code /me}) keeps the
 * same id; puts it in the logging context and logs one access line, then echoes it on the response.
 * Grep the id and this service's part of a cross-service journey shows up next to everyone else's.
 *
 * <p><b>The access line masks addresses in the path.</b> Two admin endpoints name their subject in
 * a path segment ({@code PUT /admin/users/{email}/roles} and {@code .../factors/reset}), and this
 * filter matches {@code /**} — so every admin request wrote a full e-mail address into the log, and
 * the log is shipped to Loki and kept for weeks. That is personal data leaving the database on a
 * path nothing in the deletion flow can reach. {@link MaskedEmail#maskedPath} keeps the line useful
 * (the route is still readable) without the address; the endpoints' URLs, which clients and pacts
 * depend on, stay as they are.
 */
@ServerFilter("/**")
final class CorrelationIdFilter {

    static final String HEADER = "X-Correlation-Id";
    private static final String ATTR = "cid";
    private static final Logger log = LoggerFactory.getLogger(CorrelationIdFilter.class);

    /**
     * How much of an inbound correlation id is kept, and which characters.
     *
     * <p>It is a caller-supplied string that this service then LOGS on every line of the request and
     * ECHOES in the response — so unbounded, it is a kilobyte of somebody else's text in every log
     * aggregator the estate has, repeated per line, chosen by whoever is calling. CR and LF cannot
     * enter a header value in the first place, so this is not about forging log lines; it is about
     * an id being an id. Anything outside the shape below is not one, and gets a fresh one instead.
     */
    private static final int MAX_LENGTH = 64;
    private static final java.util.regex.Pattern SHAPED =
            java.util.regex.Pattern.compile("[A-Za-z0-9._:-]{1,64}");

    @RequestFilter
    void onRequest(HttpRequest<?> request) {
        String cid = request.getHeaders().get(HEADER);
        if (cid == null || cid.isBlank() || cid.length() > MAX_LENGTH || !SHAPED.matcher(cid).matches()) {
            cid = UUID.randomUUID().toString().substring(0, 8);
        }
        request.setAttribute(ATTR, cid);
        MDC.put(ATTR, cid);
        log.info("cid={} {} {}", cid, request.getMethod(), MaskedEmail.maskedPath(request.getPath()));
    }

    @ResponseFilter
    void onResponse(HttpRequest<?> request, MutableHttpResponse<?> response) {
        request.getAttribute(ATTR, String.class).ifPresent(cid -> response.header(HEADER, cid));
        MDC.remove(ATTR);
    }
}
