package com.jrobertgardzinski.security.system.event;

public sealed interface AuthenticationResult permits AuthenticationBlocked, AuthenticationFailed, AuthenticationPassed {
}
