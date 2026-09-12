package com.jrobertgardzinski;

/**
 * A protected resource was reached without the authorization filter having published a caller —
 * which means the path is not on the filter's list, and the request is unauthenticated however it
 * got here. It answers 401 rather than 500: the caller's situation is "you are not signed in", and
 * the filter's blind spot is the service's own business (logged, not echoed).
 */
final class NotAuthenticatedException extends RuntimeException {

    NotAuthenticatedException() {
        super("no authenticated caller on this request - is the path filtered?");
    }
}
