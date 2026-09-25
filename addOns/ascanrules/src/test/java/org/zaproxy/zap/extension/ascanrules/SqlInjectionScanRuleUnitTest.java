/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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

/**
 * Unit test for the generic SQL injection scan rule (id 40018).
 *
 * <p>All scenario tests are inherited from {@link SqlInjectionScanRuleTestBase}, which is shared
 * with {@link SqlInjectionScanRule424242UnitTest}, so that both rules are benchmarked with the
 * exact same set of tests. Only the rule under test is provided here.
 *
 * <p>Measured noise: in one of 19 isolated runs a single parameterized error-based case ({@code
 * [24] error = "oracle.jdbc"} of {@code shouldAlertOriginalParamPrefixMediumThreshold}) reported no
 * alert; 18 further runs of the same scenarios were clean. The scenarios are unchanged from the
 * pre-existing suite and no source of randomness was found in the rule or in {@code
 * UrlParamValueHandler}, so a lone failing parameterized error case is not yet a trustworthy
 * difference signal - rerun before drawing conclusions from it.
 */
class SqlInjectionScanRuleUnitTest extends SqlInjectionScanRuleTestBase<SqlInjectionScanRule> {

    @Override
    protected SqlInjectionScanRule createScanner() {
        mockMessages(new ExtensionAscanRules());
        return new SqlInjectionScanRule();
    }
}
