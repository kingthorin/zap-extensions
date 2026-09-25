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
package org.zaproxy.zap.extension.ascanrules;

import org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionModularScanRule;

/**
 * Unit test for the temporary SQL injection replacement scan rule (id 424242).
 *
 * <p>All scenario tests are inherited from {@link SqlInjectionScanRuleTestBase}, which is shared
 * with {@link SqlInjectionScanRuleUnitTest}, so that both rules are benchmarked with the exact same
 * set of tests. Only the rule under test is provided here; scenarios which fail for this rule (and
 * pass for the generic rule) are the signal the benchmark is meant to surface.
 *
 * <p>Recorded baseline when the shared scenarios were introduced (329 scenarios per rule, each
 * wrapper run on its own): 40018 passes all 329, this rule fails 247 - 230 error-based, 8
 * boolean-based, 7 outer (alert mappings, tech targeting, expression confirmation, message budget),
 * 1 five-hundred and 1 union. These are recorded results, not outstanding test work: they say where
 * this rule behaves differently from the generic one, and only the rule should change to move them.
 */
class SqlInjectionScanRule424242UnitTest
        extends SqlInjectionScanRuleTestBase<SqlInjectionModularScanRule> {

    @Override
    protected SqlInjectionModularScanRule createScanner() {
        mockMessages(new ExtensionAscanRules());
        return new SqlInjectionModularScanRule();
    }
}
