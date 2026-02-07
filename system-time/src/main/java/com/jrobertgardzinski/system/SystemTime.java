package com.jrobertgardzinski.system;

import java.time.Clock;

public class SystemTime {
    private static Clock clock = Clock.systemDefaultZone();

    public static Clock currentClock() {
        return clock;
    }

    public static void setFixedTime(Clock clock) {
        SystemTime.clock = clock;
    }

    public static void reset() {
        clock = Clock.systemDefaultZone();
    }
}
