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
 */
class SqlInjectionScanRule424242UnitTest
        extends SqlInjectionScanRuleTestBase<SqlInjectionModularScanRule> {

    @Override
    protected SqlInjectionModularScanRule createScanner() {
        mockMessages(new ExtensionAscanRules());
        return new SqlInjectionModularScanRule();
    }

    @Override
    protected boolean alertsOnBare500WithoutDbErrorText() {
        // A bare 500 with no database error text is also what input validation looks like; this
        // rule requires database content (see ErrorBasedDetectionStrategyUnitTest).
        return false;
    }

    @Override
    protected boolean isLoginBypassPayload(String value) {
        // LoginBypassDetectionStrategy never sends an OR tautology: it anchors the bypass to the
        // value already in the request instead, appending "' -- " so the SQL comment drops
        // everything after it -- including the password check -- without widening which rows the
        // query matches or affects (see that class's javadoc; confirmed live against a local
        // AltoroJ container, where "jsmith' -- " logs in as jsmith with any password).
        //
        // Recognise exactly that shape here: ends with the comment suffix, and excludes "AND" so
        // this can't also match the strategy's own restrict-verify probe ("<value>' AND
        // '1'='2' -- "), which must NOT look logged in for the real alert to fire. Falling back to
        // the superclass's OR check too costs nothing and keeps this rule's own LOGINBYPASS
        // technique the only one asserted against, rather than a coincidence from another
        // technique's payload shape.
        boolean isAnchoredBypass =
                value != null && value.endsWith("' -- ") && !value.contains("AND");
        return isAnchoredBypass || super.isLoginBypassPayload(value);
    }
}
