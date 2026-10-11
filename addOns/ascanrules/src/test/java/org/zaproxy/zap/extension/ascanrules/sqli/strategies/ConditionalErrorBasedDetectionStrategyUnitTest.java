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
import static org.hamcrest.Matchers.containsString;
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
 * Integration test for {@link ConditionalErrorBasedDetectionStrategy}, exercised through the full
 * {@link SqlInjectionModularScanRule} orchestrator against a real (embedded) HTTP server, matching
 * the repo's existing NanoHTTPD-based scan rule test convention.
 */
class ConditionalErrorBasedDetectionStrategyUnitTest
        extends AbstractSqlInjectionModularScanRuleTest {

    @Test
    void shouldAlertWhenDbErrorAppearsOnlyOnTrueCondition() throws Exception {
        // Given: a page whose CASE WHEN TRUE branch divides by zero (raising a database error)
        // while
        // the FALSE branch returns a harmless literal. Only the injected condition moves the
        // needle.
        String path = "/sqli/conderror/true-errors/";
        nano.addHandler(new ConditionalErrorHandler(path, "id"));
        rule.init(getHttpMessage(path + "?id=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("id")));
        assertThat(alertsRaised.get(0).getAttack(), containsString("CASE WHEN (1=1)"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                containsString("Database error raised only when"));
    }

    /**
     * WAVSEP's SInjection-FalsePositives-GET PsAndIv SyntaxErrorOnIvFailure traps (Case02/04/06): a
     * genuinely prepared-statement page whose input validation answers with a canned {@code
     * java.sql.SQLException} for ANY SQL metacharacter, regardless of the injected condition. The
     * FALSE probe errors just as the TRUE probe does, so the pair is not a discriminator and the
     * strategy must stay quiet even though the signature path (ERROR) would fire on it.
     */
    @Test
    void shouldNotAlertWhenPageErrorsOnAnySqlMetacharacter() throws Exception {
        // Given
        String path = "/sqli/conderror/errors-on-any-metachar/";
        nano.addHandler(new PreparedStatementValidationHandler(path, "id"));
        rule.init(getHttpMessage(path + "?id=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /**
     * Neither branch errors: the parameter is not injectable, so no conditional error is produced.
     */
    @Test
    void shouldNotAlertWhenNeitherBranchErrors() throws Exception {
        // Given
        String path = "/sqli/conderror/ordinary/";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse("Ordinary content, parameter ignored");
                    }
                });
        rule.init(getHttpMessage(path + "?id=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /**
     * A vulnerable query: the {@code CASE WHEN (1=1) THEN 1/0 ...} (TRUE) branch divides by zero
     * and the server reflects a database error, while the {@code (1=2)} (FALSE) branch and the
     * baseline answer normally.
     */
    private static class ConditionalErrorHandler extends NanoServerHandler {

        private final String param;

        ConditionalErrorHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (value != null && value.contains("CASE WHEN (1=1)")) {
                return newFixedLengthResponse(
                        Response.Status.INTERNAL_ERROR,
                        NanoHTTPD.MIME_HTML,
                        "<html><body>java.sql.SQLException: division by zero"
                                + " (1=1 branch evaluated)</body></html>");
            }
            return newFixedLengthResponse("Ordinary result for " + value);
        }
    }

    /**
     * A prepared-statement page with strict input validation: any SQL metacharacter answers with a
     * canned {@code java.sql.SQLException}, whether the injected condition is true or false. This
     * is the WAVSEP Case02/04/06 false-positive shape.
     */
    private static class PreparedStatementValidationHandler extends NanoServerHandler {

        private final String param;

        PreparedStatementValidationHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (value != null && containsSqlMetacharacter(value)) {
                return newFixedLengthResponse(
                        Response.Status.INTERNAL_ERROR,
                        NanoHTTPD.MIME_HTML,
                        "<html><body>Exception details: java.sql.SQLException: Invalid Input for SQL"
                                + "</body></html>");
            }
            return newFixedLengthResponse("Login page for " + value);
        }

        private static boolean containsSqlMetacharacter(String value) {
            return value.contains("'")
                    || value.contains("\"")
                    || value.contains(";")
                    || value.contains("(")
                    || value.contains("--");
        }
    }
}
