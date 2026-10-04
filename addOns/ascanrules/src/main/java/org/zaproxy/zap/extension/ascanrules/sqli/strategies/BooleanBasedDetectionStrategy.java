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
 * Detects boolean-based blind SQL injection using a restrict-then-verify approach: for each of 9
 * payload pairs, sends AND_TRUE first; if it matches the baseline, sends AND_FALSE; if AND_FALSE
 * differs from the baseline, the parameter is injectable and an alert is raised.
 *
 * <p>OR-based expansion (the old broaden fallback) is not used. An {@code OR <true expression>} in
 * a WHERE clause returns every row on a vulnerable SELECT (DoS by data volume) or deletes / updates
 * every row on a vulnerable DELETE/UPDATE. AND conditions restrict rather than expand the matched
 * row set and are therefore safe to probe.
 *
 * <p>Compares against the baseline the rule fetches once per parameter ({@link
 * ScanContext#getCachedBaseline()}), rather than fetching its own copy of the same request.
 */
public class BooleanBasedDetectionStrategy implements DetectionStrategy {

    private final ResponseComparator comparator = new ResponseComparator();

    @Override
    public boolean detect(ScanContext context) throws IOException {
        String originalValue = context.getOriginalValue() == null ? "" : context.getOriginalValue();
        int budget = context.getRemainingBudget();
        if (budget < 2) {
            // Need at least one true/false probe pair (the baseline is already fetched); skip
            // entirely (sends nothing) so LOW strength (budget 0, matching baseline rule 40018)
            // costs no requests.
            return false;
        }

        HttpMessage baseline = context.getCachedBaseline();
        int used = 0;

        for (BooleanConditionPayloads.Condition condition :
                BooleanConditionPayloads.conditionsFor(context.getAttackStrength())) {
            if (context.isStopped() || used + 2 > budget) {
                return false;
            }

            String trueValue = originalValue + condition.andTrue();
            HttpMessage trueMsg = context.newMessage();
            context.setParam(trueMsg, trueValue);
            context.sendAndReceive(trueMsg);
            used++;

            boolean trueMatchesBaseline =
                    comparator.matchesExactlyAfterStripping(
                            baseline,
                            originalValue,
                            originalValue,
                            trueMsg,
                            originalValue,
                            trueValue);

            if (!trueMatchesBaseline) {
                // AND_TRUE didn't match baseline, try next payload pair
                continue;
            }

            // AND_TRUE matches baseline; now test AND_FALSE
            if (used + 1 > budget) {
                return false;
            }

            String falseValue = originalValue + condition.andFalse();
            HttpMessage falseMsg = context.newMessage();
            context.setParam(falseMsg, falseValue);
            context.sendAndReceive(falseMsg);
            used++;

            boolean falseDiffersFromBaseline =
                    !comparator.matchesExactlyAfterStripping(
                            baseline,
                            originalValue,
                            originalValue,
                            falseMsg,
                            originalValue,
                            falseValue);

            if (falseDiffersFromBaseline
                    && !comparator.isDifferenceExplainedByErrorStatus(baseline, falseMsg)) {
                // AND_TRUE~baseline AND AND_FALSE!=baseline: injectable. Alert.
                // An error page for AND_FALSE alone -- rate limited, blocked by a WAF, timed out --
                // is not a difference in results, so it does not alert.
                context.newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(context.getParamName())
                        .setAttack(trueValue)
                        .setOtherInfo(
                                "Page results were successfully manipulated using the boolean"
                                        + " conditions ["
                                        + trueValue
                                        + "] and ["
                                        + falseValue
                                        + "]")
                        .setMessage(trueMsg)
                        .raise();
                return true;
            }

            // AND_FALSE also matches baseline; no differential detected — try next pair
        }

        return false;
    }
}
