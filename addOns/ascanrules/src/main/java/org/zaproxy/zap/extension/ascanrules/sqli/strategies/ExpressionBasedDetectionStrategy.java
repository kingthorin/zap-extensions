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
 * Detects SQL injection by testing if numeric parameters are evaluated as expressions. For example,
 * if parameter "1" gives the same result as "3-2", the database is likely evaluating the
 * expression, suggesting SQL injection is possible.
 */
public class ExpressionBasedDetectionStrategy implements DetectionStrategy {

    private final ResponseComparator comparator = new ResponseComparator();

    @Override
    public boolean detect(ScanContext context) throws IOException {
        String originalValue = context.getOriginalValue() == null ? "" : context.getOriginalValue();

        // Only test for numeric parameters
        int paramAsInt;
        try {
            paramAsInt = Integer.parseInt(originalValue);
        } catch (NumberFormatException e) {
            return false;
        }

        int budget = context.getRemainingBudget();
        if (budget < 2) {
            return false; // Need the ADD pair; the MULT pair is gated on budget in the loop
        }

        // Baseline fetched once for this parameter by the rule
        HttpMessage baselineMsg = context.getCachedBaseline();
        TemplateSlot slot = new TemplateSlot();

        // Try ADD variant: if param is 1, try "3-2" and "4-2"
        try {
            int paramPlusTwo = Math.addExact(paramAsInt, 2);
            int paramPlusThree = Math.addExact(paramAsInt, 3);

            String addVariant1 = String.valueOf(paramPlusTwo) + "-2";
            String addVariant2 = String.valueOf(paramPlusThree) + "-2";

            if (2 <= budget
                    && testExpressionVariant(
                            context,
                            baselineMsg,
                            originalValue,
                            addVariant1,
                            addVariant2,
                            budget,
                            0,
                            slot)) {
                return true;
            }

            // Try MULT variant: if param is 1, try "2/2" and "4/2"
            if (4 <= budget) {
                int paramMultTwo = Math.multiplyExact(paramAsInt, 2);
                int paramMultFour = Math.multiplyExact(paramAsInt, 4);

                String multVariant1 = String.valueOf(paramMultTwo) + "/2";
                String multVariant2 = String.valueOf(paramMultFour) + "/2";

                if (testExpressionVariant(
                        context,
                        baselineMsg,
                        originalValue,
                        multVariant1,
                        multVariant2,
                        budget,
                        2,
                        slot)) {
                    return true;
                }
            }
        } catch (ArithmeticException e) {
            // Integer overflow, can't test this parameter
        }

        return false;
    }

    /**
     * Lazily-learned volatile template, shared by both variant calls of one parameter. Null
     * template means the exact-comparison path, unchanged.
     */
    private static final class TemplateSlot {
        boolean attempted;
        ResponseComparator.VolatileTemplate template;
    }

    /**
     * Learns a volatile-content template from one baseline replay, charged to this technique's
     * budget. Shared seam with the boolean strategy's learner: the derivation is strategy-agnostic
     * (baseline vs its own replay), so the wiring is one lazy fetch behind a budget check. Null
     * (give-up, budget, or a failed replay) means the exact-comparison path, unchanged.
     */
    private ResponseComparator.VolatileTemplate learnVolatileTemplate(
            ScanContext context,
            HttpMessage baselineMsg,
            String originalValue,
            int budget,
            int used)
            throws IOException {
        if (used + 1 > budget) {
            return null;
        }
        HttpMessage replay = context.getRepeatedBaseline();
        if (replay.getResponseHeader().getStatusCode()
                != baselineMsg.getResponseHeader().getStatusCode()) {
            return null;
        }
        return comparator.deriveVolatileTemplate(
                baselineMsg, originalValue, originalValue, replay, originalValue, originalValue);
    }

    private boolean testExpressionVariant(
            ScanContext context,
            HttpMessage baselineMsg,
            String originalValue,
            String variant1,
            String variant2,
            int budget,
            int used,
            TemplateSlot slot)
            throws IOException {
        // Test first variant
        HttpMessage msg1 = context.newMessage();
        context.setParam(msg1, variant1);
        context.sendAndReceive(msg1);
        used++;

        boolean variant1MatchesBaseline =
                comparator.matchesExactlyAfterStripping(
                        baselineMsg, originalValue, originalValue, msg1, originalValue, variant1);

        if (!variant1MatchesBaseline && !slot.attempted) {
            // First variant differs: either the page is volatile or the expression is not
            // evaluated. One replay tells them apart — but only with same-status pages and
            // spare budget, exactly the boolean learner's discipline.
            slot.attempted = true;
            if (msg1.getResponseHeader().getStatusCode()
                    == baselineMsg.getResponseHeader().getStatusCode()) {
                slot.template =
                        learnVolatileTemplate(context, baselineMsg, originalValue, budget, used);
                used++;
                if (slot.template != null) {
                    variant1MatchesBaseline =
                            comparator.matchesTemplate(
                                    slot.template,
                                    baselineMsg,
                                    originalValue,
                                    originalValue,
                                    msg1,
                                    originalValue,
                                    variant1);
                }
            }
        }

        if (!variant1MatchesBaseline) {
            return false; // First variant doesn't match baseline, not a valid expression test
        }
        context.recordBaselineMatch();

        // Test second variant
        HttpMessage msg2 = context.newMessage();
        context.setParam(msg2, variant2);
        context.sendAndReceive(msg2);

        boolean variant2DiffersFromBaseline;
        boolean variant2DiffersFromVariant1;
        if (slot.template != null) {
            // ponytail: variant2-vs-variant1 under a template is approximated as
            // "variant1-in minus variant2-out" rather than a template derived from msg1,
            // because deriving a second template costs another replay. Sound for the
            // alert direction (IN variants only differ by their arithmetic value), and
            // a template miss on variant2 fails closed to "no alert".
            boolean variant2MatchesBaseline =
                    comparator.matchesTemplate(
                            slot.template,
                            baselineMsg,
                            originalValue,
                            originalValue,
                            msg2,
                            originalValue,
                            variant2);
            variant2DiffersFromBaseline = !variant2MatchesBaseline;
            variant2DiffersFromVariant1 = !variant2MatchesBaseline;
        } else {
            variant2DiffersFromBaseline =
                    !comparator.matchesExactlyAfterStripping(
                            baselineMsg,
                            originalValue,
                            originalValue,
                            msg2,
                            originalValue,
                            variant2);
            variant2DiffersFromVariant1 =
                    !comparator.matchesExactlyAfterStripping(
                            msg1, originalValue, variant1, msg2, originalValue, variant2);
        }
        boolean wouldAlert = variant2DiffersFromBaseline && variant2DiffersFromVariant1;

        // An error page for the confirming expression alone -- e.g. a parameter cast to an integer,
        // where the confirming expression resolves to a non-existent id -- is not a difference in
        // results, so it does not alert.
        if (comparator.isDifferenceExplainedByErrorStatus(baselineMsg, msg2)) {
            if (wouldAlert) {
                context.recordSuppressedDifferential();
            }
            return false;
        }

        if (wouldAlert) {
            // Expressions are being evaluated: baseline = variant1 but both differ from variant2
            context.newAlert()
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setParam(context.getParamName())
                    .setAttack(variant1)
                    .setOtherInfo(
                            "Parameter evaluates SQL expressions: ["
                                    + originalValue
                                    + "] == ["
                                    + variant1
                                    + "] != ["
                                    + variant2
                                    + "]")
                    .setMessage(msg1)
                    .raise();
            return true;
        }

        return false;
    }
}
