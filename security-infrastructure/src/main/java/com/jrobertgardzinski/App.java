package com.jrobertgardzinski;

import io.micronaut.runtime.Micronaut;

import java.util.TimeZone;

public class App {
    public static void main(String[] args) {
        // Everything this service decides is decided in UTC: the Clock bean is Clock.systemUTC()
        // and every timestamp column is a TIMESTAMP without a zone holding UTC. The one place the
        // JVM's own zone still leaked in was JDBC — an Instant is bound through java.sql.Timestamp,
        // which converts using the DEFAULT zone — so the saga rows written by the container (UTC)
        // read two hours out in a service started from an IDE in Europe/Warsaw, which is exactly
        // how this estate is worked on. Set once, before anything reads a clock or a row.
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        // before the context exists: an undeclared start must be refused by name, not die on
        // whichever eager bean happens to miss its DataSource first (see ProfileGuard)
        ProfileGuard.requireDeclaredProfile(System.getProperty("micronaut.environments",
                System.getenv().getOrDefault("MICRONAUT_ENVIRONMENTS", "")));
        Micronaut.run(App.class, args);
    }
}
