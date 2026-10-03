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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.zaproxy.zap.testutils.RequestCondition.param;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeader;
import org.zaproxy.zap.extension.ascanrules.sqli.AbstractSqlInjectionModularScanRuleTest;
import org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionModularScanRule;
import org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionScenarioCorpus;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.UrlParamValueHandler;

/**
 * Integration test for {@link ExpressionBasedDetectionStrategy}, exercised through the full {@link
 * SqlInjectionModularScanRule} orchestrator against a real (embedded) HTTP server.
 */
class ExpressionBasedDetectionStrategyUnitTest extends AbstractSqlInjectionModularScanRuleTest {

    @Test
    void shouldAlertWhenExpressionIsEvaluated() throws Exception {
        String path = "/sqli/expression/injectable/";
        nano.addHandler(new ExpressionEvaluatingHandler(path, "id"));
        rule.init(getHttpMessage(path + "?id=1"), parent);

        rule.scan();

        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldNotAlertWhenExpressionIsNotEvaluated() throws Exception {
        String path = "/sqli/expression/safe/";
        nano.addHandler(new NonExpressionEvaluatingHandler(path, "id"));
        rule.init(getHttpMessage(path + "?id=1"), parent);

        rule.scan();

        assertThat(alertsRaised, is(empty()));
    }

    /**
     * A numeric parameter that the application casts to an integer, as WordPress does with its
     * {@code ?p=} page id: every existing id returns the same empty page and every non-existing id
     * returns a 404. The confirming expression resolves to a non-existing id, so the only thing
     * distinguishing it from the baseline is the error page -- reported as zaproxy/zaproxy#8651 for
     * {@code ?p=} and zaproxy/zaproxy#9289 for a plain numeric form field.
     */
    @Test
    void shouldNotAlertWhenMissingIdOnlyDiffersByErrorStatus() throws Exception {
        // Given
        String path = "/sqli/expression/int-cast/";
        nano.addHandler(
                UrlParamValueHandler.builder()
                        .targetPath(path)
                        .targetParam("id")
                        .when(
                                param("id")
                                        .matches(
                                                value ->
                                                        EXISTING_IDS.contains(
                                                                leadingDigits(value))))
                        .thenReturn("")
                        .when(param("id").matches(value -> true))
                        .thenReturn(NOT_FOUND, "Not found")
                        .build());

        // When
        rule.init(getHttpMessage(path + "?id=1"), parent);
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /**
     * The same {@code ?p=} cast as {@link #shouldNotAlertWhenMissingIdOnlyDiffersByErrorStatus()},
     * but with WordPress's canonical redirects: an existing id answers {@code 301} to its page and
     * a non-existing id answers {@code 404}. This rule follows redirects, so what it compares are
     * the landing pages, which differ per id -- it must not alert (reported as
     * zaproxy/zaproxy#8651).
     */
    @Test
    void shouldNotAlertWhenPageIdsRedirectToDifferentPages() throws Exception {
        // Given: the landing pages are registered first, as the server routes a request to the
        // first
        // handler whose path is a prefix of the request path, and these only see followed
        // redirects.
        nano.addHandler(
                new NanoServerHandler("/page/") {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String id = session.getUri().substring("/page/".length());
                        return NanoHTTPD.newFixedLengthResponse("Page " + id);
                    }
                });
        String path = "/sqli/expression/page-id/";
        nano.addHandler(new PageIdRedirectHandler(path, "id"));

        // When
        rule.init(getHttpMessage(path + "?id=1"), parent);
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /**
     * Page ids that exist, shared with the corpus so both describe the same int-cast application.
     */
    private static final Set<String> EXISTING_IDS = SqlInjectionScenarioCorpus.EXISTING_IDS;

    private static final int NOT_FOUND = 404;

    /**
     * The leading integer of a value, which is what an application that casts the parameter to an
     * integer effectively uses: {@code 3-2} starts from 3 and {@code 2/2} from 2.
     *
     * @param value the parameter value sent
     * @return the leading digits, or an empty string if there are none
     */
    private static String leadingDigits(String value) {
        return SqlInjectionScenarioCorpus.leadingDigits(value);
    }

    /**
     * A page id parameter cast to an integer: an existing id answers {@code 301} to the page, a
     * non-existing id answers {@code 404}, like WordPress does with {@code ?p=}.
     */
    private static class PageIdRedirectHandler extends NanoServerHandler {

        private final String param;

        PageIdRedirectHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String id = leadingDigits(getFirstParamValue(session, param));
            if (!EXISTING_IDS.contains(id)) {
                return NanoHTTPD.newFixedLengthResponse(
                        Response.Status.NOT_FOUND, NanoHTTPD.MIME_HTML, "Not found");
            }
            Response response =
                    NanoHTTPD.newFixedLengthResponse(
                            // WordPress sends 301; the code itself is immaterial here, as this
                            // rule follows the redirect and compares the landing page.
                            Response.Status.REDIRECT, NanoHTTPD.MIME_HTML, "");
            response.addHeader(HttpHeader.LOCATION, "/page/" + id + "/");
            return response;
        }
    }

    /**
     * Handler that evaluates numeric expressions. For example, if id=1, id=3-2, and id=2-1 all
     * return the same content, but id=4-2 returns different content, this suggests SQL injection.
     */
    private static class ExpressionEvaluatingHandler extends NanoServerHandler {
        private final String param;

        ExpressionEvaluatingHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (value == null) {
                value = "";
            }

            // Try to evaluate as expression
            try {
                int result = evaluateExpression(value);
                if (result == 1) {
                    return NanoHTTPD.newFixedLengthResponse(
                            "User ID: " + result + ", Data: Secret Info");
                } else {
                    return NanoHTTPD.newFixedLengthResponse("User ID: " + result + ", Data: ");
                }
            } catch (Exception e) {
                return NanoHTTPD.newFixedLengthResponse("Error processing: " + value);
            }
        }

        private int evaluateExpression(String expr) throws Exception {
            // Simple expression evaluator for testing
            if (expr.contains("+")) {
                String[] parts = expr.split("\\+");
                return Integer.parseInt(parts[0].trim()) + Integer.parseInt(parts[1].trim());
            } else if (expr.contains("-")) {
                String[] parts = expr.split("-");
                if (parts.length == 2) {
                    return Integer.parseInt(parts[0].trim()) - Integer.parseInt(parts[1].trim());
                }
            } else if (expr.contains("/")) {
                String[] parts = expr.split("/");
                return Integer.parseInt(parts[0].trim()) / Integer.parseInt(parts[1].trim());
            }
            return Integer.parseInt(expr);
        }
    }

    /** Handler that doesn't evaluate expressions - just returns the same content for all values. */
    private static class NonExpressionEvaluatingHandler extends NanoServerHandler {
        private final String param;

        NonExpressionEvaluatingHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            // Always return the same content, ignoring the parameter
            return NanoHTTPD.newFixedLengthResponse("User ID: 1, Data: Secret Info");
        }
    }
}
