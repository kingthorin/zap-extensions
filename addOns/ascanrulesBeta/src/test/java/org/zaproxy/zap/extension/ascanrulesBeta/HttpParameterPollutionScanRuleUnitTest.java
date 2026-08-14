/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

class HttpParameterPollutionScanRuleUnitTest
        extends ActiveScannerTest<HttpParameterPollutionScanRule> {

    @Override
    protected HttpParameterPollutionScanRule createScanner() {
        return new HttpParameterPollutionScanRule();
    }

    @AfterEach
    void tearDown() {
        rule.setAttackStrength(Plugin.AttackStrength.MEDIUM);
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(20)));
        assertThat(wasc, is(equalTo(20)));
        assertThat(tags.size(), is(equalTo(5)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2025_A05_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_04_PARAM_POLLUTION.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2025_A05_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2025_A05_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INPV_04_PARAM_POLLUTION.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_04_PARAM_POLLUTION.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlerts() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then - one example per alertRef (20014-1 through 20014-5)
        assertThat(alerts.size(), is(equalTo(5)));
    }

    @Test
    void shouldNotAlertOnConsistentResponses() throws HttpMalformedHeaderException {
        // Given - server returns same content regardless of parameter modifications
        String path = "/test";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(
                                Response.Status.OK,
                                NanoHTTPD.MIME_HTML,
                                "<html><body>Static response body</body></html>");
                    }
                });
        HttpMessage msg = getHttpMessage(path + "?id=value");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then - no impedance mismatch, no alerts
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldDetectParameterImpedanceMismatch() throws HttpMalformedHeaderException {
        // Given - server behavior differs with duplicate parameters (impedance mismatch)
        // This tests the core HPP detection: R3 response differs from both R1 and R2
        String path = "/test";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        List<String> ids = session.getParameters().get("id");
                        String response;
                        if (ids == null || ids.isEmpty()) {
                            response = "ERROR: no id parameter";
                        } else if (ids.size() == 1) {
                            // Single parameter: echo the value
                            response = "ID: " + ids.get(0);
                        } else {
                            // Multiple parameters: respond differently (impedance!)
                            response = "MULTIPLE IDS DETECTED: " + ids.size();
                        }
                        return newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, response);
                    }
                });
        HttpMessage msg = getHttpMessage(path + "?id=testvalue");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then - impedance detected (multiple params → different response)
        assertThat(alertsRaised, hasSize(1));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("provideParameterPriorityScenarios")
    void shouldNotAlertOnServerParameterPriority(String scenario, boolean useLast)
            throws HttpMalformedHeaderException {
        // Given - server uses parameter priority rule (takes first or last parameter value when
        // duplicated)
        // R1: id=original → "SELECTED: original"
        // R2: id=canary → "SELECTED: canary"
        // R3: id=original&id=canary → "SELECTED: original|canary" (matches R1 or R2, not
        // impedance)
        String path = "/test";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        List<String> ids = session.getParameters().get("id");
                        if (ids == null || ids.isEmpty()) {
                            return newFixedLengthResponse(
                                    Response.Status.OK, NanoHTTPD.MIME_HTML, "SELECTED: none");
                        }
                        String selected = useLast ? ids.get(ids.size() - 1) : ids.get(0);
                        return newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, "SELECTED: " + selected);
                    }
                });
        HttpMessage msg = getHttpMessage(path + "?id=original");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then - no impedance (R3 matches R1 or R2 behavior), no alert
        assertThat(alertsRaised, hasSize(0));
    }

    static Stream<Arguments> provideParameterPriorityScenarios() {
        return Stream.of(Arguments.of("first-wins", false), Arguments.of("last-wins", true));
    }

    @Test
    void shouldNotAlertOnNoisyBaselineAfterHeuristicTune() throws HttpMalformedHeaderException {
        // Given - server returns dynamic content (e.g., timestamps, CSRF tokens) each response
        // but the canary injection doesn't cause meaningful structural change
        // Heuristic tuning (CR1.tuneHeuristicsWithResponse(CR1b)) should reduce noise
        String path = "/test";
        final AtomicInteger counter = new AtomicInteger(0);
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        int count = counter.incrementAndGet();
                        List<String> ids = session.getParameters().get("id");
                        String idValue = (ids != null && !ids.isEmpty()) ? ids.get(0) : "none";
                        // Dynamic token changes each request, but structure is consistent
                        String token = "token_" + count;
                        return newFixedLengthResponse(
                                Response.Status.OK,
                                NanoHTTPD.MIME_HTML,
                                "<html><body>ID: "
                                        + idValue
                                        + "<br/>CSRF: "
                                        + token
                                        + "</body></html>");
                    }
                });
        HttpMessage msg = getHttpMessage(path + "?id=original");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then - heuristic tuning should prevent false alert despite dynamic content
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldDetectParameterImpedanceMismatchInFormData() throws HttpMalformedHeaderException {
        // Given - server behavior differs with duplicate form parameters (impedance mismatch)
        // Tests POST form-data, distinct from query string parameters
        String path = "/test";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        List<String> ids = session.getParameters().get("id");
                        String response;
                        if (ids == null || ids.isEmpty()) {
                            response = "ERROR: no id parameter";
                        } else if (ids.size() == 1) {
                            response = "ID: " + ids.get(0);
                        } else {
                            // Multiple parameters: respond differently (impedance)
                            response = "MULTIPLE IDS DETECTED: " + ids.size();
                        }
                        return newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, response);
                    }
                });
        HttpMessage msg = getHttpMessage("POST", path, "<html></html>");
        msg.getRequestHeader().setHeader("Content-Type", "application/x-www-form-urlencoded");
        String formBody = "id=testvalue";
        msg.getRequestHeader().setHeader("Content-Length", String.valueOf(formBody.length()));
        msg.setRequestBody(formBody);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then - impedance detected in form data (should be 1 like query string test, not 2)
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldNotAlertOnVolatileBaseline() throws HttpMalformedHeaderException {
        // Given - server returns highly dynamic content (timestamps, tokens)
        // that varies significantly even with same parameter value
        String path = "/test";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        // Return very different content on each request (volatile baseline)
                        String timestamp = String.valueOf(System.currentTimeMillis());
                        String token = "token_" + UUID.randomUUID();
                        String uuid = UUID.randomUUID().toString();
                        return newFixedLengthResponse(
                                Response.Status.OK,
                                NanoHTTPD.MIME_HTML,
                                "<html><body>ID: original<br/>Time: "
                                        + timestamp
                                        + "<br/>Token: "
                                        + token
                                        + "<br/>UUID: "
                                        + uuid
                                        + "</body></html>");
                    }
                });
        HttpMessage msg = getHttpMessage(path + "?id=original");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then - baseline too volatile, no alert should be raised
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertWhenDuplicateParameterCausesError() throws HttpMalformedHeaderException {
        // Given - server rejects duplicate parameters with error response
        // R1/R2 return 200, R3 returns 400 (parameter validation)
        String path = "/test";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(NanoHTTPD.IHTTPSession session) {
                        List<String> ids = session.getParameters().get("id");
                        if (ids != null && ids.size() > 1) {
                            // Reject duplicate parameters with error
                            return newFixedLengthResponse(
                                    Response.Status.BAD_REQUEST,
                                    NanoHTTPD.MIME_HTML,
                                    "Error: Invalid request - duplicate parameters");
                        }
                        if (ids == null || ids.isEmpty()) {
                            return newFixedLengthResponse(
                                    Response.Status.OK, NanoHTTPD.MIME_HTML, "ID: none");
                        }
                        return newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, "ID: " + ids.get(0));
                    }
                });
        HttpMessage msg = getHttpMessage(path + "?id=testvalue");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then - R3 error response filtered out, no alert
        assertThat(alertsRaised, hasSize(0));
    }
}
