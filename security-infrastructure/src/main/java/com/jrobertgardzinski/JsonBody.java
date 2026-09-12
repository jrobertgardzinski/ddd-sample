package com.jrobertgardzinski;

import java.util.Map;

/**
 * Reads one text field out of a JSON body without trusting its type.
 *
 * The endpoints below bind {@code Map<String, Object>} and used to cast the value: {@code (String)
 * body.get("token")}. A caller sending {@code {"token": 123}} therefore got a 500 quoting
 * {@code class java.lang.Integer cannot be cast to class java.lang.String}, and one omitting the
 * field got an NPE from the value object — two internal errors for two ordinary client mistakes.
 *
 * A field the caller sent as something other than text is, to the domain, a field they did not
 * send: this returns null, and the value object's own rule ("must not be blank", "cannot be null
 * or blank") decides the answer. The endpoint then refuses in its own vocabulary instead of
 * leaking a stack trace.
 */
final class JsonBody {

    private JsonBody() {}

    static String text(Map<String, ?> body, String field) {
        Object value = body == null ? null : body.get(field);
        return value instanceof String text ? text : null;
    }

    /**
     * Whether a field the endpoint cannot work without is absent — missing, not text, or blank.
     * A blank ticket used to reach {@code ConcurrentHashMap.get(null)} and a blank password the
     * value object's own rule, each answering 500 with the internal sentence.
     */
    static boolean missing(Map<String, ?> body, String field) {
        String value = text(body, field);
        return value == null || value.isBlank();
    }
}
