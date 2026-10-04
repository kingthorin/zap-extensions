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

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascanrules.sqli.DbErrorSignatures;
import org.zaproxy.zap.extension.ascanrules.sqli.ScanContext;

/**
 * Guards the techniques that treat a database error response as evidence: a page that already
 * errors on a value with no SQL metacharacters at all is erroring on anything, so a signature match
 * on a payload says nothing about the payload.
 *
 * <p>An earlier revision also had a {@code detectsStrictInputValidation} check, which vetoed a
 * signature hit when the appended safe-suffix control looked like the baseline while the attack did
 * not. That is also exactly the shape of a genuine error-based injection -- normal page for a
 * benign value, database error for a quote -- so it cancelled real hits: the AltoroJ Derby error (a
 * 200 whose body names the parse error) and every generic JDBC/ODBC signature asserted by {@code
 * SqlInjectionScanRuleTestBase}'s parameterised error tests. The control check below is the
 * evidence-based part and is what remains.
 */
public final class StrictInputValidationGuard {

    private StrictInputValidationGuard() {}

    /**
     * Whether a value with no SQL metacharacters at all (the scan's cached control value) already
     * makes the page answer with a database error signature.
     *
     * <p>Some pages (WAVSEP's honeypot false-positive traps) return a generic SQL-error-shaped
     * response for <em>any</em> input, so a signature match on an attack payload says nothing about
     * the payload. When the benign control value trips the same signature, strategies must not
     * treat a signature match as evidence of injection.
     *
     * <p>ponytail: this bails out wholesale rather than trying to separate payload-specific errors
     * from generic ones; upgrade path is comparing the matched fragment/status of control and
     * attack responses if a page legitimately errors on both.
     *
     * @param context the scan context
     * @return true if the cached control response carries a database error signature
     */
    public static boolean errorsOnBenignInput(ScanContext context) {
        HttpMessage controlMsg = context.getCachedControl();
        return controlMsg != null
                && DbErrorSignatures.identify(controlMsg.getResponseBody().toString()).isPresent();
    }
}
