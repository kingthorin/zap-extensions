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
import static org.zaproxy.zap.testutils.RequestCondition.param;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.zap.extension.ascanrules.sqli.AbstractSqlInjectionModularScanRuleTest;
import org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionModularScanRule;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.UrlParamValueHandler;

/**
 * Integration test for {@link OrderByDetectionStrategy}, exercised through the full {@link
 * SqlInjectionModularScanRule} orchestrator against a real (embedded) HTTP server.
 *
 * <p>ORDER BY budgets are zero below HIGH strength (mirroring rule 40018), so these tests run at
 * {@link AttackStrength#HIGH}.
 */
class OrderByDetectionStrategyUnitTest extends AbstractSqlInjectionModularScanRuleTest {

    @Test
    void shouldAlertWhenValidOrderByIsAcceptedAndOutOfRangeIndexIsRejected() throws Exception {
        // Given: a page whose baseline matches zero rows. A valid ORDER BY index therefore changes
        // nothing, while an out-of-range index fails while the query is planned -- the differential
        // the strategy's second oracle keys on.
        String path = "/sqli/orderby/index-rejected/";
        nano.addHandler(
                UrlParamValueHandler.builder()
                        .targetPath(path)
                        .targetParam("username")
                        .when(param("username").matches(v -> v.contains("ORDER BY 99")))
                        .thenReturnHtml(REJECTED_INDEX_VIEW)
                        .fallbackHtmlResponse(DEFAULT_VIEW)
                        .build());
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?username=test"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("username")));
    }

    /** Positive control for the order oracle: DESC reverses the rows and the page is stable. */
    @Test
    void shouldAlertWhenDescReversesRowsOnAStablePage() throws Exception {
        // Given
        String path = "/sqli/orderby/desc-stable/";
        nano.addHandler(new MovableOrderByHandler(path, "sort", false, 200));
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?sort=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @ParameterizedTest
    @ValueSource(ints = {403, 429, 500})
    void shouldNotAlertWhenDescOnlyTurnsIntoAnErrorStatus(int status) throws Exception {
        // Given
        String path = "/sqli/orderby/desc-error/";
        nano.addHandler(new MovableOrderByHandler(path, "sort", false, status));
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?sort=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldNotAlertWhenPageMovesAfterAscAndTheReplayNoLongerMatches() throws Exception {
        // Given: the page changes on its own once DESC has been served, so the replayed original
        // no longer matches the baseline: the DESC difference is the page moving, not the ordering.
        String path = "/sqli/orderby/moving/";
        nano.addHandler(new MovableOrderByHandler(path, "sort", true, 200));
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?sort=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @ParameterizedTest
    @ValueSource(ints = {403, 429, 500})
    void shouldNotAlertWhenOutOfRangeIndexOnlyTurnsIntoAnErrorStatus(int status) throws Exception {
        // Given: a baseline matching zero rows, a valid index that behaves like it, and an
        // out-of-range index answered with an error status.
        String path = "/sqli/orderby/index-error/";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String value = getFirstParamValue(session, "username");
                        if (value != null && value.contains("ORDER BY 99")) {
                            return newFixedLengthResponse(
                                    Response.Status.lookup(status), "text/html", DEFAULT_VIEW);
                        }
                        return newFixedLengthResponse(DEFAULT_VIEW);
                    }
                });
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?username=test"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldNotAlertWhenPageIgnoresOrderByPayloads() throws Exception {
        // Given: the parameter is not used at all, so neither ORDER BY index can move the response.
        String path = "/sqli/orderby/static/";
        nano.addHandler(
                UrlParamValueHandler.builder()
                        .targetPath(path)
                        .targetParam("username")
                        .fallbackHtmlResponse("Default view, parameter not used")
                        .build());
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?username=test"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldAlertOnVolatilePageWhenTemplateAbsorbsCounter() throws Exception {
        // Given: an ORDER BY position page rotating a per-request counter line. Exact
        // comparisons never hold (every body differs), so without the volatile template
        // this is a false negative; with it ASC matches and DESC differs.
        String path = "/sqli/orderby/volatile/";
        nano.addHandler(new VolatileOrderByHandler(path, "sort"));
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?sort=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("sort")));
    }

    @Test
    void shouldNotAlertOnVolatilePageWhenOrderByHasNoEffect() throws Exception {
        // Given: a volatile page that ignores ORDER BY payloads — the counter moves but
        // ordering never changes, so the template must absorb everything and stay silent.
        String path = "/sqli/orderby/volatile-static/";
        nano.addHandler(new VolatileStaticOrderByHandler(path, "sort"));
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?sort=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /**
     * Serves the same body for every value except an out-of-range ORDER BY index, which gets a
     * different fallback page. The body deliberately avoids SQL error text so the error-based
     * strategy cannot be the one raising the alert.
     */
    private static final String DEFAULT_VIEW = "Default view, no records to display";

    private static final String REJECTED_INDEX_VIEW = "Fallback page for an unusable query";

    /**
     * An ORDER BY position page: {@code ASC} and the original value answer {@code alpha, beta},
     * {@code DESC} answers {@code beta, alpha} (or {@code descStatus} when it is not 200). When
     * {@code movesAfterDesc} is set, every answer after the first {@code DESC} is the reversed
     * order, as if the page changed on its own.
     */
    private static class MovableOrderByHandler extends NanoServerHandler {

        private final String param;
        private final boolean movesAfterDesc;
        private final int descStatus;
        private boolean moved;

        MovableOrderByHandler(String path, String param, boolean movesAfterDesc, int descStatus) {
            super(path);
            this.param = param;
            this.movesAfterDesc = movesAfterDesc;
            this.descStatus = descStatus;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            boolean desc =
                    value != null && value.toUpperCase(java.util.Locale.ROOT).contains("DESC");
            if (desc && movesAfterDesc) {
                moved = true;
            }
            String body =
                    desc || moved
                            ? "<table><tr><td>beta</td></tr><tr><td>alpha</td></tr></table>"
                            : "<table><tr><td>alpha</td></tr><tr><td>beta</td></tr></table>";
            if (desc && descStatus != 200) {
                return newFixedLengthResponse(
                        Response.Status.lookup(descStatus), "text/html", body);
            }
            return newFixedLengthResponse(body);
        }
    }

    /**
     * WAVSEP Case05 shape, with the listed rows changing between requests (another page writing to
     * the same table): ASC never matches the baseline, but a valid sort position still gets a list
     * while an out-of-range one gets exactly the page a bad value gets. The parameter name marks it
     * as a sort parameter, so ORDER BY runs before UNION.
     */
    @Test
    void shouldAlertWhenSortPositionIsRejectedLikeABadValueWhileRowsChange() throws Exception {
        // Given
        String path = "/sqli/orderby/sort-position/";
        nano.addHandler(new SortClauseHandler(path, true));
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?orderby=msgid"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getAttack(), is(equalTo("msgid,99")));
        assertThat(
                "ORDER BY ran ahead of UNION: " + rule.getTechniqueRequests(),
                rule.getTechniqueRequests().containsKey("UNION"),
                is(false));
    }

    /** A sort parameter checked against a list of allowed values accepts no appended position. */
    @Test
    void shouldNotAlertWhenTheSortValueIsCheckedAgainstAnAllowList() throws Exception {
        // Given
        String path = "/sqli/orderby/allow-list/";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String value = getFirstParamValue(session, "orderby");
                        return newFixedLengthResponse(
                                "msgid".equals(value) || "title".equals(value)
                                        ? "<html><body><table><tr><td>1</td></tr>"
                                                + "<tr><td>2</td></tr></table></body></html>"
                                        : "<html><body>Unknown sort column</body></html>");
                    }
                });
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?orderby=msgid"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /**
     * A date bound to a prepared statement, on a database that parses dates leniently: {@code
     * 2010-02-02,1} reads as a valid date and time and {@code 2010-02-02,99} does not, which looks
     * like an accepted and a rejected sort position but is only the date parsing (WAVSEP's 200Valid
     * Case14 answers the same way).
     */
    @Test
    void shouldNotAlertWhenADateIsParsedLenientlyByTheDatabase() throws Exception {
        // Given
        String path = "/sqli/orderby/lenient-date/";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String value = getFirstParamValue(session, "transactionDate");
                        boolean parses =
                                value != null
                                        && value.matches("2010-02-02([ ,T:]([01]?\\d|2[0-3]))?");
                        return newFixedLengthResponse(
                                parses ? "Query executed" : "Information is unavailable");
                    }
                });
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?transactionDate=2010-02-02"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /**
     * {@code SELECT msgid, title, message FROM messages ORDER BY <value>}: a valid ORDER BY
     * expression lists the rows, an invalid one is a database error the page reports as
     * "Information is unavailable". With {@code drifting}, a row comes and goes between requests.
     */
    private static class SortClauseHandler extends NanoServerHandler {

        private static final java.util.regex.Pattern VALID =
                java.util.regex.Pattern.compile(
                        "(?i)^msgid(\\s+(ASC|DESC))?(\\s+--\\s*)?$|^msgid,[1-3]$");

        private final boolean drifting;
        private int writes;

        SortClauseHandler(String path, boolean drifting) {
            super(path);
            this.drifting = drifting;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, "orderby");
            if (value == null || !VALID.matcher(value).matches()) {
                return newFixedLengthResponse(
                        "<html><body>Information is unavailable</body></html>");
            }
            java.util.List<String> rows =
                    new java.util.ArrayList<>(
                            java.util.List.of(
                                    "<tr><td>1</td><td>Welcome</td></tr>",
                                    "<tr><td>2</td><td>Remember</td></tr>",
                                    "<tr><td>3</td><td>Expire</td></tr>"));
            // Another writer adds a row on every other request and removes it again.
            if (drifting && writes++ % 2 == 1) {
                rows.add(1, "<tr><td>4</td><td>Added by another page</td></tr>");
            }
            if (value.toUpperCase(java.util.Locale.ROOT).contains("DESC")) {
                java.util.Collections.reverse(rows);
            }
            return newFixedLengthResponse(
                    "<html><body><table>" + String.join("", rows) + "</table></body></html>");
        }
    }

    /**
     * An ORDER BY position page rotating a per-request counter line: {@code ASC} and a valid index
     * keep the natural order, {@code DESC} reverses it, an out-of-range index errors.
     */
    private static class VolatileOrderByHandler extends NanoServerHandler {

        private final String param;
        private int render;

        VolatileOrderByHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            String upper = value == null ? "" : value.toUpperCase(java.util.Locale.ROOT);
            String rows = "<tr><td>alpha</td></tr><tr><td>beta</td></tr>";
            if (upper.contains("DESC")) {
                rows = "<tr><td>beta</td></tr><tr><td>alpha</td></tr>";
            } else if (upper.contains("ORDER BY 99")) {
                rows = "<tr><td>unknown column</td></tr>";
            }
            return newFixedLengthResponse(
                    "<html><body><div>render "
                            + (render++)
                            + "</div><table>"
                            + rows
                            + "</table></body></html>");
        }
    }

    /**
     * A volatile page that ignores ordering entirely: the counter moves every request but the rows
     * never do, so a template that cries injection here is a false positive.
     */
    private static class VolatileStaticOrderByHandler extends NanoServerHandler {

        private final String param;
        private int render;

        VolatileStaticOrderByHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            getFirstParamValue(session, param);
            return newFixedLengthResponse(
                    "<html><body><div>render "
                            + (render++)
                            + "</div><table><tr><td>alpha</td></tr></table></body></html>");
        }
    }
}
