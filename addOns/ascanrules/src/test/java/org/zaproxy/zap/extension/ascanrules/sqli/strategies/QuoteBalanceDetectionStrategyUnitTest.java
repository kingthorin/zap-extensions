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
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.zap.extension.ascanrules.sqli.AbstractSqlInjectionModularScanRuleTest;
import org.zaproxy.zap.testutils.NanoServerHandler;

/**
 * Unit test for {@link QuoteBalanceDetectionStrategy}, through the rule, against pages shaped like
 * WAVSEP's no-row cases: Case01 (a login that matches nothing) and Case03 (a count of "No Match."),
 * where any SQL exception is replaced by one fixed text.
 */
class QuoteBalanceDetectionStrategyUnitTest extends AbstractSqlInjectionModularScanRuleTest {

    private static final String NO_MATCH = "<html><body>login failed</body></html>";
    private static final String UNAVAILABLE =
            "<html><body>Information is unavailable</body></html>";

    private static long quotes(String value) {
        return value == null ? 0 : value.chars().filter(c -> c == '\'').count();
    }

    private String serve(String path, Function<String, Response> page) {
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return page.apply(getFirstParamValue(session, "user"));
                    }
                });
        return path;
    }

    private static Response ok(String body) {
        return newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, body);
    }

    private void scan(String path) throws Exception {
        rule.setAttackStrength(AttackStrength.MEDIUM);
        rule.init(getHttpMessage(path + "?user=smith"), parent);
        rule.scan();
    }

    /** An odd number of quotes breaks the query, an even number is an escaped literal. */
    @Test
    void shouldAlertWhenOddQuotesBreakThePageAndEvenQuotesRepairIt() throws Exception {
        // Given
        String path = serve("/qb/login/", v -> ok(quotes(v) % 2 == 1 ? UNAVAILABLE : NO_MATCH));

        // When
        scan(path);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("user")));
        assertThat(alertsRaised.get(0).getAttack(), is(equalTo("smith'")));
    }

    @Test
    void shouldNotAlertWhenPageIgnoresTheParameter() throws Exception {
        // Given
        String path = serve("/qb/ignored/", v -> ok(NO_MATCH));

        // When
        scan(path);

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldNotAlertWhenPageEchoesTheValueAndNothingElseChanges() throws Exception {
        // Given
        String path = serve("/qb/echo/", v -> ok("<p>No results for " + v + "</p>"));

        // When
        scan(path);

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /** A validator that rejects any quote answers the doubled quote like the lone one. */
    @Test
    void shouldNotAlertWhenPageRejectsEveryQuote() throws Exception {
        // Given
        String path = serve("/qb/reject/", v -> ok(quotes(v) > 0 ? UNAVAILABLE : NO_MATCH));

        // When
        scan(path);

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /** A page that answers anything but the exact original value the same way is not reacting. */
    @Test
    void shouldNotAlertWhenPageOnlyKnowsTheOriginalValue() throws Exception {
        // Given
        String path = serve("/qb/exact/", v -> ok("smith".equals(v) ? "found smith" : NO_MATCH));

        // When
        scan(path);

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /** A bare 5xx on the lone quote is the error-status case the other techniques also skip. */
    @Test
    void shouldNotAlertWhenOnlyTheStatusTurnsIntoAnError() throws Exception {
        // Given
        String path =
                serve(
                        "/qb/status/",
                        v ->
                                quotes(v) % 2 == 1
                                        ? newFixedLengthResponse(
                                                Response.Status.INTERNAL_ERROR,
                                                NanoHTTPD.MIME_HTML,
                                                NO_MATCH)
                                        : ok(NO_MATCH));

        // When
        scan(path);

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /** A lone quote with no row-matching baseline must not alert on a numeric parameter. */
    @Test
    void shouldNotRunOnNumericParameter() throws Exception {
        // Given
        String path = serve("/qb/numeric/", v -> ok(quotes(v) % 2 == 1 ? UNAVAILABLE : NO_MATCH));
        rule.setAttackStrength(AttackStrength.MEDIUM);
        rule.init(getHttpMessage(path + "?user=42"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldSendNothingAtLowStrength() throws Exception {
        // Given
        String path = serve("/qb/low/", v -> ok(quotes(v) % 2 == 1 ? UNAVAILABLE : NO_MATCH));
        rule.setAttackStrength(AttackStrength.LOW);
        rule.init(getHttpMessage(path + "?user=smith"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }
}
