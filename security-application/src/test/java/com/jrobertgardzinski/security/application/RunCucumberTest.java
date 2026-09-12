package com.jrobertgardzinski.security.application;

import org.junit.platform.suite.api.*;

import static io.cucumber.junit.platform.engine.Constants.FILTER_TAGS_PROPERTY_NAME;
import static io.cucumber.junit.platform.engine.Constants.GLUE_PROPERTY_NAME;
import static io.cucumber.junit.platform.engine.Constants.PLUGIN_PROPERTY_NAME;

@Suite
@IncludeEngines("cucumber")
// the features below are shared from the top-level specs/ dir (build-helper puts them on the
// classpath root) and selected explicitly, so the one Gherkin file per use case drives both this
// runner and the HTTP-level runners. FIVE of the nineteen run here — this layer drives the use-case
// objects directly, so a feature only joins when its glue exists at this level; the rest are driven
// over HTTP (and most of them in the browser as well).
@SelectClasspathResource("register.feature")
@SelectClasspathResource("authenticate.feature")
@SelectClasspathResource("refresh-session.feature")
@SelectClasspathResource("federated-sign-in.feature")
@SelectClasspathResource("mfa.feature")
@ConfigurationParameter(key = PLUGIN_PROPERTY_NAME, value = "html:target/report.html")
@ConfigurationParameter(key = GLUE_PROPERTY_NAME, value = "com.jrobertgardzinski.security.application.feature")
// features tagged @wip (not yet implemented) are excluded from the run
@ConfigurationParameter(key = FILTER_TAGS_PROPERTY_NAME, value = "not @wip")
public class RunCucumberTest {
}