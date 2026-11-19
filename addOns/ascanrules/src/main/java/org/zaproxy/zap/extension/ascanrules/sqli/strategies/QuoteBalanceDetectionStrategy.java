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
import org.zaproxy.zap.extension.ascanrules.sqli.ParameterContext;
import org.zaproxy.zap.extension.ascanrules.sqli.ResponseComparator;
import org.zaproxy.zap.extension.ascanrules.sqli.ScanContext;

/**
 * Detects SQL injection into a string literal on pages whose baseline matches no rows, by checking
 * whether the query reacts to the balance of quotes in the value.
 *
 * <p>The boolean technique cannot work there: AND-true and AND-false are both evaluated against an
 * empty result set, so both answer like the baseline. A quote does not need rows. Unbalanced, it
 * breaks the query and the page changes (often to a fixed error message with no database error
 * text); doubled, it is an escaped literal quote, the query is valid again, and the page is back to
 * the baseline. Nothing widens the matched rows: the repaired value only ever matches rows whose
 * value contains the literal quote, so it is safe against {@code UPDATE} and {@code DELETE} as
 * well.
 *
 * <p>An alert needs all of the following, so a page that answers the probes differently for some
 * other reason does not raise one:
 *
 * <ul>
 *   <li>the lone quote changes the response, and not only by turning it into an error status;
 *   <li>the benign control did not produce the same response (the page does not just answer
 *       anything unexpected that way);
 *   <li>the doubled quote answers like the baseline;
 *   <li>a second unbalanced value (three quotes) answers like the lone quote.
 * </ul>
 *
 * <p>When the baseline matches rows, the doubled quote no longer matches them and the check stays
 * silent; that case belongs to the boolean technique. A page that moves on every request also stays
 * silent, because the comparison is exact.
 */
public class QuoteBalanceDetectionStrategy implements DetectionStrategy {

    /** Requests the check can send: the lone quote, the doubled quote, and three quotes. */
    static final int REQUESTS = 3;

    private final ResponseComparator comparator = new ResponseComparator();

    @Override
    public boolean detect(ScanContext context) throws IOException {
        ParameterContext parameterContext = context.getParameterContext();
        if (context.getRemainingBudget() < REQUESTS
                || (parameterContext != null && parameterContext.isNumericContext)) {
            return false;
        }

        String originalValue = context.getOriginalValue() == null ? "" : context.getOriginalValue();
        HttpMessage baseline = context.getCachedBaseline();
        HttpMessage control = context.getCachedControl();
        if (control == null || StrictInputValidationGuard.errorsOnBenignInput(context)) {
            return false;
        }
        String controlValue = originalValue + ScanContext.CONTROL_SUFFIX;

        String breakValue = originalValue + "'";
        HttpMessage breakMsg = send(context, breakValue);
        if (matches(originalValue, baseline, originalValue, breakMsg, breakValue)) {
            return false;
        }
        if (comparator.isDifferenceExplainedByErrorStatus(baseline, breakMsg)) {
            context.recordSuppressedDifferential();
            return false;
        }
        if (matches(originalValue, control, controlValue, breakMsg, breakValue)) {
            return false;
        }

        if (context.isStopped()) {
            return false;
        }
        String repairValue = originalValue + "''";
        HttpMessage repairMsg = send(context, repairValue);
        if (!matches(originalValue, baseline, originalValue, repairMsg, repairValue)) {
            return false;
        }
        context.recordBaselineMatch();

        if (context.isStopped()) {
            return false;
        }
        String secondBreakValue = originalValue + "'''";
        HttpMessage secondBreakMsg = send(context, secondBreakValue);
        if (matches(originalValue, baseline, originalValue, secondBreakMsg, secondBreakValue)
                || !matches(
                        originalValue, breakMsg, breakValue, secondBreakMsg, secondBreakValue)) {
            return false;
        }

        context.newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setParam(context.getParamName())
                .setAttack(breakValue)
                .setOtherInfo(
                        "The response changed when the quote count was odd ["
                                + breakValue
                                + "], ["
                                + secondBreakValue
                                + "] and went back to the original when it was even ["
                                + repairValue
                                + "]")
                .setMessage(breakMsg)
                .raise();
        return true;
    }

    private HttpMessage send(ScanContext context, String value) throws IOException {
        HttpMessage message = context.newMessage();
        context.setParam(message, value);
        context.sendAndReceive(message);
        return message;
    }

    /** Whether two responses are the same page once the value each was sent is stripped out. */
    private boolean matches(
            String originalValue,
            HttpMessage one,
            String oneValue,
            HttpMessage other,
            String otherValue) {
        return comparator.matchesExactlyAfterStripping(
                one, originalValue, oneValue, other, originalValue, otherValue);
    }
}
