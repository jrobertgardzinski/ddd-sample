package com.jrobertgardzinski.security.application.event;

public sealed interface AuthenticationResult permits AuthenticationBlocked, AuthenticationFailed, AuthenticationPassed {
}
