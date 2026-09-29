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

import java.io.IOException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascanrules.sqli.DbErrorSignatures;
import org.zaproxy.zap.extension.ascanrules.sqli.ResponseComparator;
import org.zaproxy.zap.extension.ascanrules.sqli.ScanContext;

/**
 * Detects pages with excessively strict input validation that reject any appended characters, not
 * just SQL injection payloads. Such pages are false positives for injection detection strategies
 * that rely on appending payloads.
 *
 * <p>The guard works by: (1) appending a safe, non-SQL-metacharacter suffix to the original value,
 * (2) comparing the response to the baseline, and (3) flagging as strict if the baseline and
 * safe-suffix responses are similar (page accepts the safe suffix) while the attack response
 * differs significantly (page rejects the attack payload). This signature indicates the page is
 * selectively rejecting payloads, not accepting all input equally.
 */
public final class StrictInputValidationGuard {

    /** A suffix with no SQL metacharacters, used to detect overly-strict input validation. */
    public static final String SAFE_SUFFIX = "S4feV4lu3";

    private static final ResponseComparator comparator = new ResponseComparator();

    private StrictInputValidationGuard() {}

    /**
     * Checks whether the page rejects any appended suffix (including safe ones), indicating strict
     * input validation rather than SQL injection vulnerability.
     *
     * @param context the scan context
     * @param originalValue the original parameter value
     * @param baseline the response from the original value
     * @param attackMsg the response from the attacked value
     * @param attackValue the actual attacked value sent
     * @return true if the page appears to have strict input validation (honeypot signature), false
     *     otherwise
     * @throws IOException if network communication fails
     */
    public static boolean detectsStrictInputValidation(
            ScanContext context,
            String originalValue,
            HttpMessage baseline,
            HttpMessage attackMsg,
            String attackValue)
            throws IOException {
        HttpMessage controlMsg = context.newMessage();
        context.setParam(controlMsg, originalValue + SAFE_SUFFIX);
        context.sendAndReceive(controlMsg);

        // If baseline ~ control (safe suffix produces similar response to original),
        // but attack differs, the page is selectively rejecting SQL payloads:
        // a signature of strict input validation rather than real injection.
        boolean baselineControlSimilar =
                comparator.isSimilar(
                        baseline, originalValue, controlMsg, originalValue + SAFE_SUFFIX);
        boolean attackDiffers =
                comparator.isDifferent(baseline, originalValue, attackMsg, attackValue);

        return baselineControlSimilar && attackDiffers;
    }

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
