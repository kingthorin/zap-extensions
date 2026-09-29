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

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.zap.extension.ascanrules.sqli.AbstractSqlInjectionModularScanRuleTest;
import org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionModularScanRule;
import org.zaproxy.zap.testutils.NanoServerHandler;

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
        nano.addHandler(new OrderByIndexHandler(path, "username"));
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?username=test"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("username")));
    }

    @Test
    void shouldNotAlertWhenPageIgnoresOrderByPayloads() throws Exception {
        // Given: the parameter is not used at all, so neither ORDER BY index can move the response.
        String path = "/sqli/orderby/static/";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse("Default view, parameter not used");
                    }
                });
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(getHttpMessage(path + "?username=test"), parent);

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
    private static class OrderByIndexHandler extends NanoServerHandler {

        private static final String DEFAULT_VIEW = "Default view, no records to display";
        private static final String REJECTED_INDEX_VIEW = "Fallback page for an unusable query";

        private final String param;

        OrderByIndexHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (value != null && value.contains("ORDER BY 99")) {
                return newFixedLengthResponse(REJECTED_INDEX_VIEW);
            }
            return newFixedLengthResponse(DEFAULT_VIEW);
        }
    }
}
