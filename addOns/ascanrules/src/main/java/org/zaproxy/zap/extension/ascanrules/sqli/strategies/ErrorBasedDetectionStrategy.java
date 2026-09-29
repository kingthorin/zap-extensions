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
import java.util.List;
import java.util.Optional;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascanrules.sqli.DbErrorSignatures;
import org.zaproxy.zap.extension.ascanrules.sqli.DbErrorSignatures.Dbms;
import org.zaproxy.zap.extension.ascanrules.sqli.DetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.ResponseComparator;
import org.zaproxy.zap.extension.ascanrules.sqli.ScanContext;

/**
 * Detects SQL injection by breaking the query with a metacharacter and recognizing a database error
 * signature ({@link DbErrorSignatures}) in the response.
 *
 * <p>Unlike the generic rule (40018), a raw error-signature match here is never itself sufficient:
 * some pages (see WAVSEP's honeypot false-positive traps) return a generic SQL-error-shaped
 * response for <em>any</em> malformed input, not specifically because of the SQL metacharacter.
 * Before alerting, this strategy re-sends the same parameter with a value that contains no SQL
 * metacharacters at all; if that control request produces the same error signature, the page errors
 * on anything, and this is not evidence of injection.
 */
public class ErrorBasedDetectionStrategy implements DetectionStrategy {

    /** String-context payloads: wrapped in quotes. */
    private static final List<String> ERROR_PAYLOADS_STRING =
            List.of("'", "\"", "';", "\");", "'(");

    /** Numeric-context payloads: no quotes needed. */
    private static final List<String> ERROR_PAYLOADS_NUMERIC =
            List.of("+NULL", ",NULL", " NULL", " OR NULL", " AND NULL");

    /** Fallback payloads for unknown context. */
    private static final List<String> ERROR_PAYLOADS_FALLBACK =
            List.of("'", "\"", "';", "\");", "'(", ")", "NULL", "'\"");

    private final ResponseComparator comparator = new ResponseComparator();

    @Override
    public boolean detect(ScanContext context) throws IOException {
        String originalValue = context.getOriginalValue() == null ? "" : context.getOriginalValue();
        int budget = context.getRemainingBudget();
        int used = 0;

        // Reuse cached baseline from scan initialization
        HttpMessage baseline = context.getCachedBaseline();
        if (baseline == null) {
            baseline = context.newMessage();
            context.setParam(baseline, originalValue);
            context.sendAndReceive(baseline);
            used++;
        }

        // Early exit: if baseline itself contains an error signature, the page is broken
        if (DbErrorSignatures.identify(baseline.getResponseBody().toString()).isPresent()) {
            return false;
        }

        // Early exit: if a value with no SQL metacharacters at all already errors, the page errors
        // on anything, so a signature match on a payload is not evidence of injection.
        if (StrictInputValidationGuard.errorsOnBenignInput(context)) {
            return false;
        }

        List<String> payloads = selectPayloads(context);

        for (String payload : payloads) {
            // Probe the bare payload first (the value replaced entirely), then the payload appended
            // to the original value: the generic rule (40018) sends the empty prefix first, so the
            // reported attack value matches the shape that broke the page.
            if (context.isStopped() || used >= budget) {
                return false;
            }

            HttpMessage bareMsg = context.newMessage();
            context.setParam(bareMsg, payload);
            context.sendAndReceive(bareMsg);
            used++;

            if (raiseOnResponse(context, baseline, bareMsg, payload)) {
                return true;
            }

            if (context.isStopped() || used >= budget) {
                return false;
            }

            String attackValue = originalValue + payload;
            HttpMessage attackMsg = context.newMessage();
            context.setParam(attackMsg, attackValue);
            context.sendAndReceive(attackMsg);
            used++;

            if (raiseOnResponse(context, baseline, attackMsg, attackValue)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks one probe response and raises an alert if it is conclusive: either a known DB error
     * signature (subject to the strict-input-validation guard) or a server error the baseline and
     * control requests did not produce (a quote that reliably breaks the page). The caller has
     * already spent the request and checked the budget, so nothing is counted here.
     *
     * @return true if an alert was raised
     */
    private boolean raiseOnResponse(
            ScanContext context, HttpMessage baseline, HttpMessage attackMsg, String attackValue)
            throws IOException {
        Optional<Dbms> dbms = DbErrorSignatures.identify(attackMsg.getResponseBody().toString());
        if (dbms.isPresent()) {
            if (StrictInputValidationGuard.detectsStrictInputValidation(
                    context, context.getOriginalValue(), baseline, attackMsg, attackValue)) {
                return false;
            }

            String evidence =
                    dbms.get()
                            .findMatchedFragment(attackMsg.getResponseBody().toString())
                            .orElse(dbms.get().getLabel());
            context.newAlert()
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setParam(context.getParamName())
                    .setAttack(attackValue)
                    .setEvidence(evidence)
                    .setOtherInfo("Likely RDBMS: " + dbms.get().getLabel())
                    .setMessage(attackMsg)
                    .raise();
            return true;
        }

        // A payload that turns a working baseline into a server error (while a safe control value
        // does not) is itself evidence of injection: pages don't 500 on benign input.
        if (isServerError(attackMsg)
                && !isServerError(baseline)
                && (context.getCachedControl() == null
                        || !isServerError(context.getCachedControl()))) {
            context.newAlert()
                    .setConfidence(Alert.CONFIDENCE_LOW)
                    .setParam(context.getParamName())
                    .setAttack(attackValue)
                    .setEvidence(attackMsg.getResponseHeader().getPrimeHeader().trim())
                    .setMessage(attackMsg)
                    .raise();
            return true;
        }
        return false;
    }

    private static boolean isServerError(HttpMessage msg) {
        int status = msg.getResponseHeader().getStatusCode();
        return status >= 500 && status < 600;
    }

    private List<String> selectPayloads(ScanContext context) {
        var paramCtx = context.getParameterContext();
        if (paramCtx == null) {
            return ERROR_PAYLOADS_FALLBACK;
        }
        if (paramCtx.isNumericContext) {
            return ERROR_PAYLOADS_NUMERIC;
        }
        if (paramCtx.isStringLiteralContext) {
            return ERROR_PAYLOADS_STRING;
        }
        return ERROR_PAYLOADS_FALLBACK;
    }
}
