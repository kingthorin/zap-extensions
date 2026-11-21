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
import static org.hamcrest.Matchers.startsWith;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.zap.extension.ascanrules.sqli.AbstractSqlInjectionModularScanRuleTest;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.UrlParamValueHandler;

/**
 * Integration test for {@link UnionBasedDetectionStrategy} based on WAVSEP test case:
 * SQL-Injection/SInjection-Detection-Evaluation-GET-200Error/Case02-InjectionInSearch-String-UnionExploit-With200Errors.jsp
 *
 * <p>Tests UNION-based SQL injection in a LIKE clause where: - Normal query: SELECT msgid, title,
 * message FROM messages WHERE message like'<input>%' - UNION attack: message like'' UNION ALL
 * SELECT ... -- %' - Expected response: Either UNION error signature or different data (3 columns
 * expected)
 */
class UnionBasedDetectionStrategyUnitTest extends AbstractSqlInjectionModularScanRuleTest {

    @Test
    void shouldAlertOnUnionBasedInjectionInLikeClause() throws Exception {
        // WAVSEP Case02: UNION-based SQLi in a LIKE clause with 200 Error responses
        String path = "/sqli/union/search/";
        nano.addHandler(new UnionInjectableHandler(path, "msg"));
        rule.init(getHttpMessage(path + "?msg=test"), parent);

        rule.scan();

        assertThat("Should detect UNION-based injection in LIKE clause", alertsRaised, hasSize(1));
    }

    /** Engines differ in the case of their messages; the match must not depend on it. */
    @Test
    void shouldAlertWhenUnionErrorFragmentCaseDiffersFromTheSignature() throws Exception {
        // Given
        String path = "/sqli/union/lowercase/";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String value = getFirstParamValue(session, "msg");
                        if (value != null
                                && value.toLowerCase(java.util.Locale.ROOT).contains("union")) {
                            return newFixedLengthResponse(
                                    NanoHTTPD.Response.Status.OK,
                                    NanoHTTPD.MIME_HTML,
                                    "the used select statements have a different number of"
                                            + " columns");
                        }
                        return newFixedLengthResponse(normalResponse());
                    }
                });
        rule.init(getHttpMessage(path + "?msg=test"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                is(equalTo("The used SELECT statements have a different number of columns")));
    }

    @Test
    void shouldNotAlertOnNormalSearchQuery() throws Exception {
        // A search page that returns the same results no matter what is put in the parameter:
        // nothing for the UNION strategy to exploit, so the rule must stay quiet.
        String path = "/sqli/union/search/";
        nano.addHandler(
                UrlParamValueHandler.builder()
                        .targetPath(path)
                        .targetParam("msg")
                        .fallbackHtmlResponse(normalResponse())
                        .build());
        rule.init(getHttpMessage(path + "?msg=hello"), parent);

        rule.scan();

        // Normal query should not trigger alert
        assertThat(alertsRaised, empty());
    }

    /**
     * WAVSEP Case15 shape: an unquoted date that matches no rows, so AND-true and AND-false look
     * alike and only the UNION can show anything. A UNION with the query's four columns adds a row;
     * any other count fails like any other bad input. The boolean probes leave the unquoted closing
     * behind, which is what the column count is sent with.
     */
    @Test
    void shouldAlertWhenExactlyOneColumnCountIsAccepted() throws Exception {
        // Given
        String path = "/sqli/union/column-count/";
        nano.addHandler(new ColumnCountHandler(path, 4, false, false));
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?transactionDate=2010-02-02"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getConfidence(), is(Alert.CONFIDENCE_MEDIUM));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo("2010-02-02 UNION ALL SELECT NULL,NULL,NULL,NULL -- ")));
        assertThat(rule.getParameterContext().getLearnedClosing(), is(equalTo("")));
    }

    /** The same page on an engine with md5(): the canary at the found count makes it HIGH. */
    @Test
    void shouldAlertHighWhenTheCanaryAtTheFoundColumnCountIsComputed() throws Exception {
        // Given
        String path = "/sqli/union/column-count-md5/";
        ColumnCountHandler handler = new ColumnCountHandler(path, 4, true, false);
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?transactionDate=2010-02-02"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getConfidence(), is(Alert.CONFIDENCE_HIGH));
        assertThat(
                alertsRaised.get(0).getAttack(),
                startsWith("2010-02-02 UNION ALL SELECT NULL,NULL,NULL,md5('"));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo(handler.lastHash())));
    }

    /**
     * Rows that change on every request (another page writing to the same table) do not hide the
     * column count: the rejected counts all get the same error page, which does not move with the
     * data.
     */
    @Test
    void shouldAlertOnColumnCountWhenTheListedRowsChangeOnEveryRequest() throws Exception {
        // Given
        String path = "/sqli/union/column-count-drifting/";
        nano.addHandler(new ColumnCountHandler(path, 4, false, true));
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?transactionDate=2010-02-02"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo("2010-02-02 UNION ALL SELECT NULL,NULL,NULL,NULL -- ")));
    }

    /**
     * A strictly validated numeric id: it answers anything but an existing id with the same
     * "invalid id" page, so every column count answers alike and none stands out.
     */
    @Test
    void shouldNotAlertWhenPageAnswersEveryColumnCountLikeTheControl() throws Exception {
        // Given
        String path = "/sqli/union/strict-id/";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String value = getFirstParamValue(session, "id");
                        return newFixedLengthResponse(
                                "5".equals(value)
                                        ? "<html><body><h1>Widget</h1><p>Price 10, in stock,"
                                                + " ships today</p></body></html>"
                                        : "<html><body>invalid id</body></html>");
                    }
                });
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?id=5"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @ParameterizedTest
    @ValueSource(ints = {400, 403, 429, 500})
    void shouldNotAlertWhenUnionOnlyTurnsIntoAnErrorStatus(int status) throws Exception {
        // Given: normal for the baseline and the control, an error status for any UNION.
        String path = "/sqli/union/error-status/";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String value = getFirstParamValue(session, "msg");
                        if (value != null
                                && value.toUpperCase(java.util.Locale.ROOT).contains("UNION")) {
                            return newFixedLengthResponse(
                                    Response.Status.lookup(status),
                                    NanoHTTPD.MIME_HTML,
                                    "<html><body>Request rejected</body></html>");
                        }
                        return newFixedLengthResponse(normalResponse());
                    }
                });
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?msg=test"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /**
     * A page whose answer depends on how many commas the value has (a comma-separated list filter):
     * every column count answers differently, so no single count stands out.
     */
    @Test
    void shouldNotAlertWhenEveryColumnCountAnswersDifferently() throws Exception {
        // Given
        String path = "/sqli/union/comma-list/";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String value = getFirstParamValue(session, "ids");
                        long items =
                                value == null ? 0 : value.chars().filter(c -> c == ',').count();
                        return newFixedLengthResponse(
                                "<html><body>" + (items + 1) + " items selected</body></html>");
                    }
                });
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?ids=7"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /**
     * A search on an unquoted date column, the shape of WAVSEP Case15: an {@code AND} condition is
     * accepted (matching no rows either way, as the date compares as arithmetic), a {@code UNION}
     * with the query's column count adds its row, and anything else is a database error, which the
     * page reports as "Information is unavailable".
     */
    private static class ColumnCountHandler extends NanoServerHandler {

        private static final String BASE = "2010-02-02";

        private final int columns;
        private final boolean md5;
        private final boolean drifting;
        private int writes;
        private String lastHash = "";

        ColumnCountHandler(String path, int columns, boolean md5, boolean drifting) {
            super(path);
            this.columns = columns;
            this.md5 = md5;
            this.drifting = drifting;
        }

        String lastHash() {
            return lastHash;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, "transactionDate");
            if (value == null || !value.startsWith(BASE)) {
                return error();
            }
            String rest = value.substring(BASE.length());
            if (rest.isEmpty() || rest.matches(" AND [^'\"]+ -- ")) {
                return table("");
            }
            java.util.regex.Matcher union =
                    java.util.regex.Pattern.compile("^ UNION ALL SELECT (.+) -- $").matcher(rest);
            if (!union.matches()) {
                return error();
            }
            String[] selected = union.group(1).split(",");
            if (selected.length != columns) {
                return error();
            }
            StringBuilder row = new StringBuilder("<tr>");
            for (String column : selected) {
                java.util.regex.Matcher call =
                        java.util.regex.Pattern.compile("^md5\\('([^']*)'\\)$").matcher(column);
                String cell;
                if ("NULL".equals(column)) {
                    cell = "null";
                } else if (md5 && call.matches()) {
                    try {
                        lastHash = UnionBasedDetectionStrategy.md5Hex(call.group(1));
                    } catch (Exception e) {
                        return error();
                    }
                    cell = lastHash;
                } else {
                    return error();
                }
                row.append("<td>").append(cell).append("</td>");
            }
            return table(row.append("</tr>").toString());
        }

        private Response table(String rows) {
            String written =
                    drifting ? "<tr><td>895</td><td>written " + (writes++) + "</td></tr>" : "";
            return newFixedLengthResponse(
                    "<html><body><p>The list of transactions:</p><table><tr><th>transactionId</th>"
                            + "<th>sum</th><th>description</th><th>transactionDate</th></tr>"
                            + written
                            + rows
                            + "</table></body></html>");
        }

        private static Response error() {
            return newFixedLengthResponse("<html><body>Information is unavailable</body></html>");
        }
    }

    private static String normalResponse() {
        return "<html><body><table>"
                + "<tr><td>1</td><td>Title1</td><td>Message1</td></tr>"
                + "<tr><td>2</td><td>Title2</td><td>Message2</td></tr>"
                + "</table></body></html>";
    }

    /**
     * The canary middle stage's true-positive wiring: a UNION that interpolates {@code md5(canary)}
     * into the page alerts at HIGH confidence with the server-computed hash as evidence — the value
     * the probe text never contained.
     *
     * <p>The appendage probes exhaust the MEDIUM budget before the canary probe runs (six probes,
     * budget four), so this test runs at {@link AttackStrength#HIGH} (budget nine), mirroring the
     * OrderBy wiring tests.
     */
    @Test
    void shouldAlertHighWhenUnionInterpolatesComputedMd5() throws Exception {
        // Given: a page that echoes everything but also renders md5('...') — the reflecting-union
        // corpus shape (corpus row "reflecting-union-interpolation", BLIND at MEDIUM).
        String path = "/sqli/union/reflecting/";
        ReflectingUnionHandler handler = new ReflectingUnionHandler(path, "q");
        nano.addHandler(handler);
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?q=test"), parent);

        // When
        rule.scan();

        // Then: exactly one alert, HIGH confidence, and the evidence is the hash the server
        // computed from the canary — not a string the probe (or any baseline) could contain.
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getConfidence(), is(Alert.CONFIDENCE_HIGH));
        assertThat(
                "evidence should be the server-computed hash",
                alertsRaised.get(0).getEvidence(),
                is(equalTo(handler.lastHash())));
    }

    /**
     * The false-positive side of the same stage: a page that echoes the {@code md5('...')} call
     * without evaluating it reflects the canary, never the hash, so the oracle stays quiet even at
     * HIGH strength (where the canary probe is guaranteed budget). This is the echo-only-search
     * guard, proven at the rule level rather than a threshold.
     */
    @Test
    void shouldNotAlertWhenPageEchoesTheMd5CallWithoutEvaluating() throws Exception {
        // Given: an echo-only page (no evaluation, no error text, no shape change)
        String path = "/sqli/union/echo-only/";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String value = getFirstParamValue(session, "q");
                        return newFixedLengthResponse(
                                "<html><body><p>No results for: "
                                        + (value == null ? "" : value)
                                        + "</p></body></html>");
                    }
                });
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?q=test"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /** The token helper must agree with the RFC 1321 test vectors the databases will produce. */
    @Test
    void md5HexShouldAgreeWithTheRfcVectors() throws Exception {
        assertThat(
                UnionBasedDetectionStrategy.md5Hex(""),
                is(equalTo("d41d8cd98f00b204e9800998ecf8427e")));
        assertThat(
                UnionBasedDetectionStrategy.md5Hex("abc"),
                is(equalTo("900150983cd24fb0d6963f7d28e17f72")));
    }

    /**
     * A search page echoing whatever it is given that additionally renders the hash of an {@code
     * md5('...')} argument — what a database interpolating the function into a UNION result set
     * does. Records the hash it rendered so the test can compare it against the alert evidence.
     */
    private static class ReflectingUnionHandler extends NanoServerHandler {

        private final String param;
        private String lastHash = "";

        ReflectingUnionHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        String lastHash() {
            return lastHash;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            java.util.regex.Matcher call =
                    java.util.regex.Pattern.compile(
                                    "md5\\('([^']*)'\\)", java.util.regex.Pattern.CASE_INSENSITIVE)
                            .matcher(value == null ? "" : value);
            String hash = "";
            if (call.find()) {
                try {
                    java.security.MessageDigest digest =
                            java.security.MessageDigest.getInstance("MD5");
                    StringBuilder hex = new StringBuilder();
                    for (byte b :
                            digest.digest(
                                    call.group(1)
                                            .getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
                        hex.append(String.format("%02x", b));
                    }
                    hash = hex.toString();
                    lastHash = hash;
                } catch (java.security.NoSuchAlgorithmException e) {
                    hash = "";
                }
            }
            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.OK,
                    NanoHTTPD.MIME_HTML,
                    "<html><body><p>You searched for: "
                            + (value == null ? "" : value)
                            + "</p>"
                            + (hash.isEmpty() ? "" : "<p>hash: " + hash + "</p>")
                            + "</body></html>");
        }
    }

    /**
     * Simulates WAVSEP Case02: vulnerable LIKE clause that accepts UNION payloads.
     *
     * <p>Vulnerable SQL: SELECT msgid, title, message FROM messages WHERE message like'<input>%'
     *
     * <p>When input='UNION ALL SELECT 1,2,3 --, the query becomes: SELECT msgid, title, message
     * FROM messages WHERE message like''UNION ALL SELECT 1,2,3 -- %'
     *
     * <p>Expected: Either UNION-specific error (column mismatch) or different result set with 3
     * columns.
     */
    private static class UnionInjectableHandler extends NanoServerHandler {
        private final String param;

        UnionInjectableHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (value == null || value.isEmpty()) {
                return newFixedLengthResponse(normalResponse());
            }

            // Check if UNION payload is present
            if (value.contains("UNION") || value.contains("union")) {
                // UNION payload detected — return either:
                // 1. UNION-specific error (MySQL: "different number of columns")
                // 2. Different data structure (e.g., 3-column output instead of search results)
                return newFixedLengthResponse(
                        NanoHTTPD.Response.Status.OK,
                        NanoHTTPD.MIME_HTML,
                        "ERROR: The used SELECT statements have a different number of columns");
            }

            // Non-UNION injection attempts (error-based, boolean-based) should get normal or error
            // response
            if (value.contains("'") || value.contains("\"")) {
                return newFixedLengthResponse(
                        NanoHTTPD.Response.Status.OK,
                        NanoHTTPD.MIME_HTML,
                        "ERROR in SQL syntax near '" + value + "'");
            }

            return newFixedLengthResponse(normalResponse());
        }
    }
}
