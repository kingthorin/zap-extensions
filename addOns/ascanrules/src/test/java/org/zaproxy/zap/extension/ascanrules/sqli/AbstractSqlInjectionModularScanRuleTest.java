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
package org.zaproxy.zap.extension.ascanrules.sqli;

import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascanrules.ExtensionAscanRules;
import org.zaproxy.zap.testutils.ActiveScannerTestUtils;

/**
 * Base class for the {@link SqlInjectionModularScanRule} integration tests (the rule itself and
 * each of its detection strategies), wiring up the rule under test and the message bundle.
 *
 * <p>SQL injection probing legitimately needs more requests per parameter than {@link
 * ActiveScannerTestUtils}'s generic guideline, so the recommended ceilings are raised by the same
 * amounts {@code SqlInjectionScanRuleTestBase} allows the generic rule (40018) this one is a
 * drop-in replacement for.
 */
public abstract class AbstractSqlInjectionModularScanRuleTest
        extends ActiveScannerTestUtils<SqlInjectionModularScanRule> {

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionAscanRules());
    }

    @Override
    protected SqlInjectionModularScanRule createScanner() {
        return new SqlInjectionModularScanRule();
    }

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
            case LOW:
                return recommendMax + 1;
            case MEDIUM:
            default:
                return recommendMax + 14;
            case HIGH:
                return recommendMax + 25;
            case INSANE:
                return recommendMax + 7;
        }
    }

    /**
     * Builds the request a corpus scenario is scanned with: a plain GET, or a form POST when the
     * scenario carries a body, the way the login and admin forms of the applications being modelled
     * send it.
     *
     * <p>Both the corpus and the metrics runner go through here, so a row cannot be scanned as a
     * GET by one and as a POST by the other - which is how the metrics runner once reported zero
     * requests for every POST row.
     *
     * @param scenario the scenario to build the request for
     * @return the request the rule is initialised with
     * @throws Exception if the request cannot be built
     */
    protected HttpMessage scenarioRequest(SqlInjectionScenario scenario) throws Exception {
        if (scenario.requestBody().isEmpty()) {
            return getHttpMessage(scenario.requestTarget());
        }
        HttpMessage message =
                getHttpMessage(
                        "POST",
                        scenario.requestTarget(),
                        SqlInjectionScenarioCorpus.NORMAL_CONTENT);
        message.getRequestHeader()
                .setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.FORM_URLENCODED_CONTENT_TYPE);
        message.setRequestBody(scenario.requestBody());
        return message;
    }
}
