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
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascanrules.sqli.DetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.ResponseComparator;
import org.zaproxy.zap.extension.ascanrules.sqli.ScanContext;

/**
 * Detects SQL injection via ORDER BY clause manipulation: appends " ASC -- " to the parameter and
 * checks if the response matches a fresh baseline. If so, appends " DESC -- " as confirmation —
 * both should match a properly-ordered result, but a failed injection likely produces different
 * results.
 *
 * <p>Uses a cheap cascade (baseline → ASC, then DESC only if ASC matched): typical cost is 2 or 3
 * requests. When that oracle is inconclusive and budget allows, a second oracle runs (valid vs
 * out-of-range ORDER BY index, 2 more requests), which is what detects pages whose baseline matches
 * zero rows. Full cost at HIGH strength is therefore 5 requests, the whole allocation.
 *
 * <p>Deliberately re-sends the original value rather than comparing against {@link
 * ScanContext#getBaseMessage()}: that message is stale for real scanning, so a live baseline is the
 * only reliable comparison point.
 */
public class OrderByDetectionStrategy implements DetectionStrategy {

    private final ResponseComparator comparator = new ResponseComparator();

    /** A well-formed ORDER BY with a valid index: should behave like the baseline. */
    private static final String VALID_INDEX_PAYLOAD = "' ORDER BY 1 -- ";

    /**
     * An ORDER BY with an index no result set can have. Ordering fails while the query is planned,
     * so this differs from the baseline even when the baseline matches zero rows — unlike AND-style
     * narrowing, which cannot distinguish anything against an empty result set.
     */
    private static final String OUT_OF_RANGE_INDEX_PAYLOAD = "' ORDER BY 99 -- ";

    @Override
    public boolean detect(ScanContext context) throws IOException {
        String originalValue = context.getOriginalValue() == null ? "" : context.getOriginalValue();
        int budget = context.getRemainingBudget();
        if (budget < 2) {
            // Minimum 2 requests: baseline + ASC (DESC only sent if ASC matches)
            return false;
        }

        // Send fresh baseline with original value (1 request)
        HttpMessage baseline = context.newMessage();
        context.setParam(baseline, originalValue);
        context.sendAndReceive(baseline);

        // Send ASC payload (1 request)
        String ascPayload = originalValue + " ASC -- ";
        HttpMessage ascMsg = context.newMessage();
        context.setParam(ascMsg, ascPayload);
        context.sendAndReceive(ascMsg);

        // Check if ASC matches baseline (ResponseComparator handles stripping)
        boolean ascMatchesBaseline =
                comparator.matchesExactlyAfterStripping(
                        baseline, originalValue, originalValue, ascMsg, originalValue, ascPayload);

        if (!ascMatchesBaseline) {
            // ASC doesn't match baseline — injection unlikely, bail early
            return false;
        }

        if (budget < 3) {
            // We matched, but no budget left for DESC confirmation
            return false;
        }

        // Send DESC confirmation (1 request)
        String descPayload = originalValue + " DESC -- ";
        HttpMessage descMsg = context.newMessage();
        context.setParam(descMsg, descPayload);
        context.sendAndReceive(descMsg);

        // Check if DESC differs from baseline
        boolean descDiffersFromBaseline =
                !comparator.matchesExactlyAfterStripping(
                        baseline,
                        originalValue,
                        originalValue,
                        descMsg,
                        originalValue,
                        descPayload);

        if (descDiffersFromBaseline) {
            context.newAlert()
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setParam(context.getParamName())
                    .setAttack(ascPayload)
                    .setEvidence("ORDER BY clause appears to control result ordering")
                    .setMessage(ascMsg)
                    .raise();
            return true;
        }

        return detectRejectedOrderByIndex(context, baseline, originalValue);
    }

    /**
     * Second oracle: the page accepts a valid ORDER BY index but reacts to an out-of-range one.
     *
     * <p>This is what recovers blind cases whose baseline returns zero rows: the ORDER BY index is
     * checked while the query is planned, so no row has to be matched for the difference to show.
     * It never widens or modifies the row set (unlike an OR tautology, which is deliberately not
     * used anywhere in this rule). The valid-index probe is the control: if any ORDER BY payload
     * already moves the response (echoed input, rejected syntax), the out-of-range response proves
     * nothing and no alert is raised.
     *
     * @return true if an alert was raised
     */
    private boolean detectRejectedOrderByIndex(
            ScanContext context, HttpMessage baseline, String originalValue) throws IOException {
        if (context.isStopped() || context.getRemainingBudget() < 2) {
            return false;
        }

        String validValue = originalValue + VALID_INDEX_PAYLOAD;
        HttpMessage validMsg = context.newMessage();
        context.setParam(validMsg, validValue);
        context.sendAndReceive(validMsg);

        boolean validMatchesBaseline =
                comparator.matchesExactlyAfterStripping(
                        baseline,
                        originalValue,
                        originalValue,
                        validMsg,
                        originalValue,
                        validValue);
        if (!validMatchesBaseline) {
            return false;
        }

        String invalidValue = originalValue + OUT_OF_RANGE_INDEX_PAYLOAD;
        HttpMessage invalidMsg = context.newMessage();
        context.setParam(invalidMsg, invalidValue);
        context.sendAndReceive(invalidMsg);

        boolean invalidDiffersFromBaseline =
                !comparator.matchesExactlyAfterStripping(
                        baseline,
                        originalValue,
                        originalValue,
                        invalidMsg,
                        originalValue,
                        invalidValue);
        if (!invalidDiffersFromBaseline) {
            return false;
        }

        context.newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setParam(context.getParamName())
                .setAttack(invalidValue)
                .setEvidence("ORDER BY index rejected while a valid index is accepted")
                .setMessage(invalidMsg)
                .raise();
        return true;
    }
}
