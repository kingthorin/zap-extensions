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
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.zaproxy.zap.testutils.RequestCondition.param;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.ascanrules.sqli.AbstractSqlInjectionModularScanRuleTest;
import org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionModularScanRule;
import org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionScenarioCorpus;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.UrlParamValueHandler;

/**
 * Integration test for {@link BooleanBasedDetectionStrategy}, exercised through the full {@link
 * SqlInjectionModularScanRule} orchestrator against a real (embedded) HTTP server.
 */
class BooleanBasedDetectionStrategyUnitTest extends AbstractSqlInjectionModularScanRuleTest {

    @Test
    void shouldAlertWhenBooleanConditionControlsResponse() throws Exception {
        // Given
        String path = "/sqli/boolean/injectable/";
        nano.addHandler(
                UrlParamValueHandler.builder()
                        .targetPath(path)
                        .targetParam("id")
                        .when(param("id").matches(SqlInjectionScenarioCorpus::isFalseCondition))
                        .thenReturnHtml("")
                        .fallbackHtmlResponse(TRUE_CONDITION_CONTENT)
                        .build());
        rule.init(getHttpMessage(path + "?id=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("id")));
    }

    @Test
    void shouldAlertWhenParameterIsDoubleEncoded() throws Exception {
        // Given: the page decodes the parameter a second time before using it
        String path = "/sqli/boolean/double-encoded/";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String value = getFirstParamValue(session, "id");
                        try {
                            value = java.net.URLDecoder.decode(value, "UTF-8");
                        } catch (Exception e) {
                            return newFixedLengthResponse("");
                        }
                        return newFixedLengthResponse(
                                SqlInjectionScenarioCorpus.isFalseCondition(value)
                                        ? ""
                                        : TRUE_CONDITION_CONTENT);
                    }
                });
        rule.init(getHttpMessage(path + "?id=1%2520"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldOnlyEncodePayloadWhenOriginalValueIsDoubleEncoded() {
        assertThat(
                BooleanBasedDetectionStrategy.valueToSend("1", "' AND 'a' LIKE 'a%"),
                is("1' AND 'a' LIKE 'a%"));
        assertThat(
                BooleanBasedDetectionStrategy.valueToSend("1%20", "' AND 2>1 -- "),
                is("1%20%27+AND+2%3E1+--+"));
    }

    @Test
    void shouldNotAlertWhenResponseIsAlwaysTheSame() throws Exception {
        // Given: not injectable -- the page ignores the parameter entirely, so true/false/baseline
        // are all identical and there's no differential to detect.
        String path = "/sqli/boolean/static/";
        nano.addHandler(
                UrlParamValueHandler.builder()
                        .targetPath(path)
                        .targetParam("id")
                        .fallbackHtmlResponse("Always the same content, id ignored")
                        .build());
        rule.init(getHttpMessage(path + "?id=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /**
     * The false condition of a boolean pair is answered with {@code 429 Too Many Requests} while
     * the original value and the true condition are answered normally. The reported rate limiter is
     * the only thing that differs, so there is nothing to detect -- this alerts otherwise (reported
     * as zaproxy/zaproxy#8652).
     */
    @Test
    void shouldNotAlertWhenFalseConditionIsRateLimited() throws Exception {
        assertNoAlertWhenFalseConditionGetsErrorPage(429, "too many requests");
    }

    /**
     * As {@link #shouldNotAlertWhenFalseConditionIsRateLimited()}, but the false condition is
     * rejected with {@code 403 Forbidden} by a WAF rather than rate limited: static assets served
     * with a cache-buster parameter, where any payload that looks like SQL is blocked (reported as
     * zaproxy/zaproxy#8653).
     */
    @Test
    void shouldNotAlertWhenFalseConditionIsRejectedWithForbidden() throws Exception {
        assertNoAlertWhenFalseConditionGetsErrorPage(403, "blocked by WAF");
    }

    /**
     * As {@link #shouldNotAlertWhenFalseConditionIsRateLimited()}, but the false condition is
     * answered with {@code 500 Internal Server Error}, e.g. a slow handler that times out on a
     * payload resembling a PHP injection or an expensive wildcard search (reported as
     * zaproxy/zaproxy#8525).
     */
    @Test
    void shouldNotAlertWhenFalseConditionGetsInternalServerError() throws Exception {
        assertNoAlertWhenFalseConditionGetsErrorPage(500, "Internal Server Error");
    }

    private void assertNoAlertWhenFalseConditionGetsErrorPage(int statusCode, String body)
            throws Exception {
        String path = "/sqli/boolean/error-page/";
        nano.addHandler(errorPageOnFalseConditionHandler(path, "id", statusCode, body));
        rule.init(getHttpMessage(path + "?id=1"), parent);

        rule.scan();

        assertThat(alertsRaised, is(empty()));
        // The near-miss telemetry has to show these runs: a probe matched the baseline (the first
        // gate), and the would-have-alerted differential was stopped only by the error-status
        // guard — suppressed=0 here would mean the test's gate never fired.
        assertThat(rule.getBaselineMatchCount(), is(greaterThan(0)));
        assertThat(rule.getSuppressedDifferentialCount(), is(greaterThan(0)));
    }

    private static UrlParamValueHandler errorPageOnFalseConditionHandler(
            String path, String paramName, int statusCode, String body) {
        return UrlParamValueHandler.builder()
                .targetPath(path)
                .targetParam(paramName)
                .when(param(paramName).matches(SqlInjectionScenarioCorpus::isFalseCondition))
                .thenReturn(statusCode, body)
                .fallbackHtmlResponse(TRUE_CONDITION_CONTENT)
                .build();
    }

    /** The body a page returns for the original value and for a true condition. */
    private static final String TRUE_CONDITION_CONTENT = SqlInjectionScenarioCorpus.NORMAL_CONTENT;
}
