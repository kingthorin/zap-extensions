/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrules.sqli.strategies;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.ascanrules.sqli.AbstractSqlInjectionModularScanRuleTest;
import org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionModularScanRule;
import org.zaproxy.zap.testutils.NanoServerHandler;

/**
 * Integration test for {@link ErrorBasedDetectionStrategy}, exercised through the full {@link
 * SqlInjectionModularScanRule} orchestrator against a real (embedded) HTTP server, matching the
 * repo's existing NanoHTTPD-based scan rule test convention.
 */
class ErrorBasedDetectionStrategyUnitTest extends AbstractSqlInjectionModularScanRuleTest {

    @Test
    void shouldAlertWhenSqlMetacharacterTriggersRealDbError() throws Exception {
        // Given
        String path = "/sqli/error/genuine/";
        nano.addHandler(new GenuineSqlErrorHandler(path, "id"));
        rule.init(getHttpMessage(path + "?id=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("id")));
    }

    /**
     * The AltoroJ (demo.testfire.net) login page: {@code DBUtil.isValidUser} throws Derby's parse
     * error for a quote and {@code LoginServlet} stores {@code getLocalizedMessage()} for {@code
     * login.jsp} to print verbatim -- a 200, not a 500. A safe suffix is just an unknown username,
     * so it looks like the baseline. Detection here is tautology-free: the quote alone is the whole
     * payload.
     */
    @Test
    void shouldAlertOnAltoroStyleLoginPageWithDerbyErrorInBody() throws Exception {
        // Given
        String path = "/sqli/error/altoro-login/";
        nano.addHandler(new AltoroLoginHandler(path, "uid"));
        rule.init(getHttpMessage(path + "?uid=jsmith"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("uid")));
        assertThat(alertsRaised.get(0).getAttack(), is(equalTo("'")));
    }

    @Test
    void shouldNotAlertWhenPageErrorsOnAnyMalformedInput() throws Exception {
        // Given: a WAVSEP-style honeypot -- it returns a SQL-error-shaped response for ANY
        // value other than the exact expected one, not specifically because of SQL
        // metacharacters. A naive error-signature match (with no control-value re-check) would
        // false-positive on this.
        String path = "/sqli/error/honeypot/";
        nano.addHandler(new HoneypotHandler(path, "id", "1"));
        rule.init(getHttpMessage(path + "?id=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /**
     * WAVSEP's 500ErrorOnIvFailure trap: the page 500s on any SQL metacharacter because of input
     * validation, answering with a generic exception that never mentions the database. The bare-500
     * heuristic must not treat that as injection.
     */
    @Test
    void shouldNotAlertWhenPage500sWithoutDbErrorText() throws Exception {
        // Given
        String path = "/sqli/error/no-db-text-500/";
        nano.addHandler(new InputValidation500Handler(path, "id"));
        rule.init(getHttpMessage(path + "?id=test"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldNotAlertOnOrdinaryPage() throws Exception {
        // Given
        String path = "/sqli/error/none/";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse("Some ordinary content");
                    }
                });
        rule.init(getHttpMessage(path + "?id=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /** Errors with a MySQL-shaped message only when the parameter contains a SQL metacharacter. */
    private static class GenuineSqlErrorHandler extends NanoServerHandler {

        private final String param;

        GenuineSqlErrorHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (value != null && (value.contains("'") || value.contains("\""))) {
                return newFixedLengthResponse(
                        Response.Status.INTERNAL_ERROR,
                        NanoHTTPD.MIME_HTML,
                        "Warning: You have an error in your SQL syntax near '" + value + "'");
            }
            return newFixedLengthResponse("Some ordinary content for " + value);
        }
    }

    /**
     * Mimics AltoroJ's login page: Derby's error text is printed into the body of a normal 200
     * login page, and anything without a metacharacter (including a safe suffix) just fails login.
     */
    private static class AltoroLoginHandler extends NanoServerHandler {

        private static final String LOGIN_FAILED =
                "Login Failed: We&#39;re sorry, but this username or password was not found in our"
                        + " system. Please try again.";

        private static final String DERBY_ERROR =
                "Syntax error: Encountered &quot;&lt;EOF&gt;&quot; at line 1, column 79.";

        private final String param;

        AltoroLoginHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            boolean metacharacter = value != null && value.contains("'");
            return newFixedLengthResponse(loginPage(metacharacter ? DERBY_ERROR : LOGIN_FAILED));
        }

        private static String loginPage(String message) {
            return "<!DOCTYPE html><html><head><title>Altoro Mutual</title></head><body>"
                    + "<div id=\"header\"><h1>Altoro Mutual</h1><ul id=\"nav\">"
                    + "<li><a href=\"index.jsp\">Home</a></li>"
                    + "<li><a href=\"login.jsp\">Login</a></li>"
                    + "<li><a href=\"search.jsp\">Search</a></li>"
                    + "<li><a href=\"feedback.jsp\">Feedback</a></li></ul></div>"
                    + "<div id=\"wrapper\" style=\"width: 99%;\">"
                    + "<div id=\"toc\"><h2>Online Banking</h2><p>Altoro Mutual is a fictitious"
                    + " online banking application, hosted to demonstrate application security"
                    + " testing tools. Use the form below to sign in to your account and view your"
                    + " balances, transfer funds and pay bills.</p></div>"
                    + "<h1>Online Banking Login</h1>"
                    + "<p><span id=\"_ctl0__ctl0_Content_Main_message\" style=\"color:#FF0066;"
                    + "font-size:12pt;font-weight:bold;\">"
                    + message
                    + "</span></p>"
                    + "<form action=\"doLogin\" method=\"post\" name=\"login\" id=\"login\">"
                    + "<table><tr><td>Username:</td><td><input type=\"text\" id=\"uid\""
                    + " name=\"uid\" value=\"\" style=\"width: 150px;\"></td></tr>"
                    + "<tr><td>Password:</td><td><input type=\"password\" id=\"passw\""
                    + " name=\"passw\" style=\"width: 150px;\"></td></tr>"
                    + "<tr><td></td><td><input type=\"submit\" name=\"btnSubmit\""
                    + " value=\"Login\"></td></tr></table></form></div>"
                    + "<div id=\"footer\"><p>Altoro Mutual is a demonstration application and is not"
                    + " connected to any real bank. All accounts, balances and transactions shown"
                    + " are fictitious.</p></div>"
                    + "<script type=\"text/javascript\">function setfocus() {"
                    + "if (document.login.uid.value==\"\") {document.login.uid.focus();} else"
                    + " {document.login.passw.focus();}}</script></body></html>";
        }
    }

    /** Errors with a MySQL-shaped message for any value that isn't exactly the expected one. */
    private static class HoneypotHandler extends NanoServerHandler {

        private final String param;
        private final String expectedValue;

        HoneypotHandler(String path, String param, String expectedValue) {
            super(path);
            this.param = param;
            this.expectedValue = expectedValue;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (expectedValue.equals(value)) {
                return newFixedLengthResponse("Some ordinary content for " + value);
            }
            return newFixedLengthResponse(
                    Response.Status.INTERNAL_ERROR,
                    NanoHTTPD.MIME_HTML,
                    "Warning: You have an error in your SQL syntax near '" + value + "'");
        }
    }

    /**
     * 500s with a generic, database-silent error whenever the value contains a SQL metacharacter.
     */
    private static class InputValidation500Handler extends NanoServerHandler {

        private final String param;

        InputValidation500Handler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (value != null
                    && (value.contains("'") || value.contains("\"") || value.contains(";"))) {
                return newFixedLengthResponse(
                        Response.Status.INTERNAL_ERROR,
                        NanoHTTPD.MIME_HTML,
                        "<html><body><h1>HTTP Status 500</h1><p>Exception details:"
                                + " java.lang.Exception: Invalid Input</p></body></html>");
            }
            return newFixedLengthResponse("Some ordinary content for " + value);
        }
    }
}
