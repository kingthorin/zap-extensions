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
import java.security.SecureRandom;
import java.util.List;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.http.ComparableResponse;
import org.zaproxy.zap.extension.ascanrules.sqli.DbErrorSignatures;
import org.zaproxy.zap.extension.ascanrules.sqli.DbErrorSignatures.Dbms;
import org.zaproxy.zap.extension.ascanrules.sqli.DetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.ScanContext;

/**
 * Detects UNION-based SQL injection using three stages of ascending cost:
 *
 * <p><strong>Error-based detection (primary):</strong> Appends UNION clauses and checks for
 * database-specific UNION error signatures. Uses exact UNION-specific fragments per engine
 * (verified from baseline rule 40018), filtering by {@link ScanContext#getTechSet()}.
 *
 * <p><strong>Canary-reflection detection (middle):</strong> Sends one UNION probe carrying {@code
 * md5(canary)} for a random hex canary and looks for the computed hash in the response. The DB
 * computes the hash, so the response carries hex the probe text never contains: a page that merely
 * echoes input goes quiet by construction, not by threshold. Fails closed to the diff fallback
 * below on engines without {@code md5()} (a non-evaluated token simply doesn't reflect).
 *
 * <p><strong>Response-differentiation detection (fallback):</strong> If error-based detection
 * fails, compares baseline vs UNION response for observable differences. Catches cases where UNION
 * succeeds silently (200 OK with different data), common in search/filter contexts.
 *
 * <p>Match rule: Error detection requires UNION-specific fragment absent from baseline AND present
 * in attack. Canary detection requires the computed hash present in attack AND absent from the
 * baseline. Response-diff requires responses to differ significantly (via exact matching after
 * encoding stripping), indicating successful UNION injection altering result set.
 */
public class UnionBasedDetectionStrategy implements DetectionStrategy {

    /** The 6 core UNION appendages from baseline rule 40018. */
    private static final List<String> SQL_UNION_APPENDAGES =
            List.of(
                    " UNION ALL select NULL -- ",
                    "' UNION ALL select NULL -- '",
                    "\" UNION ALL select NULL -- \"",
                    ") UNION ALL select NULL -- ",
                    "') UNION ALL select NULL -- '",
                    "\") UNION ALL select NULL -- \"");

    @Override
    public boolean detect(ScanContext context) throws IOException {
        String originalValue = context.getOriginalValue() == null ? "" : context.getOriginalValue();
        int budget = context.getRemainingBudget();
        if (budget < 1) {
            // Need at least one appendage probe (the baseline is already fetched); skip entirely so
            // LOW strength (budget 0, matching baseline rule 40018) costs no requests.
            return false;
        }

        // Get candidate engines in scope for this target
        List<Dbms> candidates = DbErrorSignatures.inTechScope(context.getTechSet());
        if (candidates.isEmpty()) {
            // No candidates in tech scope, skip (zero requests spent, budget rolls to next
            // strategy)
            return false;
        }

        // Early exit: if a value with no SQL metacharacters at all already errors, the page errors
        // on anything, so a signature match on a UNION payload is not evidence of injection.
        if (StrictInputValidationGuard.errorsOnBenignInput(context)) {
            return false;
        }

        // Baseline fetched once for this parameter by the rule
        HttpMessage baseline = context.getCachedBaseline();
        String baselineBody = baseline.getResponseBody().toString();
        String baselineStripped =
                ResponseBodyUtils.stripAllEncodedForms(baselineBody, originalValue);

        ComparableResponse baselineResp = new ComparableResponse(baseline, originalValue);

        int used = 0;
        HttpMessage lastUnionMsg = null;
        String lastUnionPayload = null;

        for (String appendage : SQL_UNION_APPENDAGES) {
            if (context.isStopped() || used >= budget) {
                return false;
            }

            String payload = originalValue + appendage;
            HttpMessage attackMsg = context.newMessage();
            context.setParam(attackMsg, payload);
            context.sendAndReceive(attackMsg);
            used++;

            String attackBody = attackMsg.getResponseBody().toString();
            String attackStripped =
                    ResponseBodyUtils.stripAllEncodedForms(attackBody, originalValue, payload);

            // Try error-based detection first (fast path)
            boolean errorDetected = false;
            for (Dbms dbms : candidates) {
                for (String unionFragment : dbms.getUnionFragments()) {
                    // Fragment absent from baseline AND present in attack => hit
                    boolean absentFromBaseline = !baselineStripped.contains(unionFragment);
                    boolean presentInAttack = attackStripped.contains(unionFragment);
                    if (absentFromBaseline && presentInAttack) {
                        context.newAlert()
                                .setConfidence(Alert.CONFIDENCE_HIGH)
                                .setParam(context.getParamName())
                                .setAttack(payload)
                                .setEvidence(unionFragment)
                                .setOtherInfo("Likely RDBMS: " + dbms.getLabel())
                                .setMessage(attackMsg)
                                .raise();
                        return true;
                    }
                }
            }

            // Save last attempt for response-differentiation fallback
            lastUnionMsg = attackMsg;
            lastUnionPayload = payload;
        }

        // Middle: canary-reflection detection for UNION that succeeds silently (200 OK, no
        // error text, computed value interpolated into the page). One probe, budget-charged
        // like any other: md5(canary) with a random canary, token = the hex the DB computes.
        // No strip: probe text and token live in disjoint alphabets, so any occurrence is
        // computed reflection, never echo. Absent-from-baseline first, so a page that
        // already contains the token cannot alert on it.
        if (!context.isStopped() && used < budget) {
            String canary = randomCanary();
            String token;
            try {
                token = md5Hex(canary);
            } catch (Exception e) {
                token = null;
            }
            if (token != null && !baselineBody.contains(token)) {
                String payload =
                        originalValue + "' UNION ALL SELECT NULL,NULL,md5('" + canary + "') -- ";
                HttpMessage canaryMsg = context.newMessage();
                context.setParam(canaryMsg, payload);
                context.sendAndReceive(canaryMsg);

                if (canaryMsg.getResponseBody().toString().contains(token)) {
                    context.newAlert()
                            .setConfidence(Alert.CONFIDENCE_HIGH)
                            .setParam(context.getParamName())
                            .setAttack(payload)
                            .setEvidence(token)
                            .setOtherInfo(
                                    "UNION-based SQLi: database evaluated md5() and reflected the computed value")
                            .setMessage(canaryMsg)
                            .raise();
                    return true;
                }
                lastUnionMsg = canaryMsg;
                lastUnionPayload = payload;
            }
        }

        // Fallback: Response-differentiation detection for cases where UNION succeeds silently
        // (200 OK but different data). Common in search/filter contexts (200Valid cases).
        // Skipped when the attack body is empty: an empty response is a generic error/fallback
        // page, not a UNION-altered result set, and comparing it against a real baseline produces
        // a mid-range similarity that false-positives on any page whose stubbed responses differ
        // from the handler fallback.
        if (lastUnionMsg != null && !lastUnionMsg.getResponseBody().toString().isBlank()) {
            String unionStripped =
                    ResponseBodyUtils.stripAllEncodedForms(
                            lastUnionMsg.getResponseBody().toString(),
                            originalValue,
                            lastUnionPayload);
            // A body that differs from the baseline only by the echoed input is echo, not an
            // altered result set: stripped-equal means there is nothing left to compare, and the
            // word-count/reflection heuristics below would otherwise score the echo itself as a
            // mid-range "difference" (echo-only FP on any page that reflects input at HIGH
            // strength, where the appendage loop finishes and this fallback is reached).
            if (unionStripped.equals(baselineStripped)) {
                return false;
            }

            ComparableResponse unionResp = new ComparableResponse(lastUnionMsg, lastUnionPayload);
            float similarity = baselineResp.compareWith(unionResp);

            // If responses differ significantly (0.01 < similarity < 0.80), UNION likely altered
            // result set
            // Skip 0% similarity (trap signature: completely broken response from security
            // frameworks)
            // and >0.80 (too similar, likely not an injection)
            // This range catches legitimate 200Valid Search-Union cases while avoiding
            // HoneyPot/PsAndIv false positives that return 0% similarity
            if (similarity > 0.0f && similarity < 0.80f) {
                context.newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(context.getParamName())
                        .setAttack(lastUnionPayload)
                        .setOtherInfo(
                                "UNION-based SQLi: response differs from baseline (similarity: "
                                        + String.format("%.0f", similarity * 100)
                                        + "%)")
                        .setMessage(lastUnionMsg)
                        .raise();
                return true;
            }
        }

        return false;
    }

    /**
     * The hex of {@code md5(canary)}, which is what a UNION result interpolates when the database
     * evaluates the function: probe text carries the call, the response carries the hash.
     *
     * <p>ponytail: {@code md5()} naming only (MySQL/Postgres); MSSQL needs {@code
     * HASHBYTES('MD5',...)} and other engines differ again. A miss there is FN-only, never FP: a
     * non-evaluated token simply doesn't reflect and the diff fallback below still runs. Ceiling is
     * one function name; upgrade is a per-{@link Dbms} function walk if the corpus ever shows a
     * silent-UNION row on a non-md5 engine.
     */
    static String md5Hex(String canary) throws Exception {
        byte[] digest =
                java.security.MessageDigest.getInstance("MD5")
                        .digest(canary.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (byte b : digest) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    private static final SecureRandom CANARY_RANDOM = new SecureRandom();

    /**
     * A random hex canary with a fixed non-hex prefix, so the token (pure hex) can never coincide
     * with the canary itself and no baseline can already contain it except by astronomical
     * coincidence.
     */
    private static String randomCanary() {
        byte[] bytes = new byte[7];
        CANARY_RANDOM.nextBytes(bytes);
        StringBuilder hex = new StringBuilder("zx");
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
}
