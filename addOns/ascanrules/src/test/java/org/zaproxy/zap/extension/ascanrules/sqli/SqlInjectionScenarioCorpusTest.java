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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Runs the corpus through {@link SqlInjectionModularScanRule} and asserts each scenario's label:
 * injectable ones alert, safe and false-positive-prone ones do not.
 *
 * <p>The labels are what makes the corpus measurable — see {@link SqlInjectionScenario}. Reporting
 * the counts across scenarios is a separate concern (the metrics runner); this test only holds
 * every row to its label.
 */
class SqlInjectionScenarioCorpusTest extends AbstractSqlInjectionModularScanRuleTest {

    static List<SqlInjectionScenario> scenarios() {
        return SqlInjectionScenarioCorpus.scenarios();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("scenarios")
    void scenarioMatchesItsLabel(SqlInjectionScenario scenario) throws Exception {
        // Given
        nano.addHandler(scenario.fixture().get());
        rule.init(getHttpMessage(scenario.requestTarget()), parent);

        // When
        rule.scan();

        // Then
        if (scenario.outcome() == SqlInjectionScenario.Outcome.INJECTABLE) {
            assertThat(alertsRaised, hasSize(greaterThan(0)));
        } else {
            assertThat(alertsRaised, is(empty()));
        }
    }
}
