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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascanrules.sqli.DbErrorSignatures;
import org.zaproxy.zap.extension.ascanrules.sqli.DbErrorSignatures.Dbms;
import org.zaproxy.zap.extension.ascanrules.sqli.DetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.ParameterContext;
import org.zaproxy.zap.extension.ascanrules.sqli.ResponseComparator;
import org.zaproxy.zap.extension.ascanrules.sqli.ScanContext;

/**
 * Detects UNION-based SQL injection in three stages of ascending cost.
 *
 * <p><strong>Error fragments:</strong> appends the UNION clauses of baseline rule 40018 and looks
 * for a database-specific UNION error (fragment absent from the baseline, present in the attack),
 * filtered by {@link ScanContext#getTechSet()}. When an earlier probe has shown how the value's SQL
 * context is closed ({@link ParameterContext#getLearnedClosing()}), only the clauses with that
 * closing are sent.
 *
 * <p><strong>Column count:</strong> a {@code UNION ALL SELECT} only parses when it has as many
 * columns as the query it is attached to, so sending {@code NULL} &times; 1, 2, 3... answers
 * differently at exactly one count. The alert needs the page to reject a bad value visibly (the
 * benign control differs from the baseline), every other count tried (at least two, including a
 * higher one) to get exactly the control's page, and the one count to get something else. A page
 * that rejects any unexpected input answers every count the same way, and a page that echoes input
 * differs only by the echo, which is stripped.
 *
 * <p><strong>Canary:</strong> a UNION carrying {@code md5(canary)} for a random canary, at the
 * column count found above when there is one. The database computes the hash, so the response
 * carries hex the probe never contains: an echo cannot produce it. A reflected hash raises the
 * alert to HIGH confidence; engines without {@code md5()} simply do not reflect it.
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

    /** The most columns the column-count stage tries, budget permitting. */
    private static final int MAX_COLUMNS = 8;

    private final ResponseComparator comparator = new ResponseComparator();

    @Override
    public boolean detect(ScanContext context) throws IOException {
        String originalValue = context.getOriginalValue() == null ? "" : context.getOriginalValue();
        if (context.getRemainingBudget() < 1) {
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

        ParameterContext parameterContext = context.getParameterContext();
        String learnedClosing =
                parameterContext == null ? null : parameterContext.getLearnedClosing();
        String closing = parameterContext == null ? "'" : parameterContext.getGuessedClosing();

        HttpMessage baseline = context.getCachedBaseline();
        String baselineBody = baseline.getResponseBody().toString();
        String baselineStripped =
                ResponseBodyUtils.stripAllEncodedForms(baselineBody, originalValue)
                        .toLowerCase(Locale.ROOT);

        // The one-column probe with the chosen closing, kept so the column-count stage need not
        // send it again.
        HttpMessage oneColumnMsg = null;
        String oneColumnPayload = null;

        for (String appendage : appendagesFor(learnedClosing, closing)) {
            if (context.isStopped()) {
                return false;
            }
            // Without a learned closing every appendage is sent, but the last request stays with
            // the canary, which does not depend on the error text.
            if (context.getRemainingBudget() < (learnedClosing == null ? 2 : 1)) {
                break;
            }

            String payload = originalValue + appendage;
            HttpMessage attackMsg = context.newMessage();
            context.setParam(attackMsg, payload);
            context.sendAndReceive(attackMsg);

            String attackStripped =
                    ResponseBodyUtils.stripAllEncodedForms(
                                    attackMsg.getResponseBody().toString(), originalValue, payload)
                            .toLowerCase(Locale.ROOT);
            for (Dbms dbms : candidates) {
                for (String unionFragment : dbms.getUnionFragments()) {
                    // Fragment absent from baseline AND present in attack => hit
                    String fragment = unionFragment.toLowerCase(Locale.ROOT);
                    if (!baselineStripped.contains(fragment) && attackStripped.contains(fragment)) {
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

            if (appendage.startsWith(closing + " UNION")) {
                oneColumnMsg = attackMsg;
                oneColumnPayload = payload;
            }
        }

        ColumnCount columnCount =
                findColumnCount(context, originalValue, closing, oneColumnMsg, oneColumnPayload);
        if (columnCount != null) {
            if (!raiseCanaryAlert(
                    context,
                    baselineBody,
                    originalValue + closing + unionSelect(columnCount.columns(), true))) {
                context.newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setParam(context.getParamName())
                        .setAttack(columnCount.payload())
                        .setOtherInfo(
                                "UNION-based SQLi: a UNION SELECT with "
                                        + columnCount.columns()
                                        + " columns was answered differently from every other"
                                        + " column count tried (1 to "
                                        + columnCount.tried()
                                        + "), and differently from a benign value")
                        .setMessage(columnCount.message())
                        .raise();
            }
            return true;
        }

        // No column count stood out (a page that renders every UNION alike, such as one that
        // echoes input next to the result): the canary at a fixed width is all that is left.
        return raiseCanaryAlert(
                context,
                baselineBody,
                originalValue
                        + closing
                        + " UNION ALL SELECT NULL,NULL,md5('"
                        + CANARY_PLACEHOLDER
                        + "') -- ");
    }

    /** A column count that answered unlike every other one tried. */
    private record ColumnCount(int columns, int tried, String payload, HttpMessage message) {}

    /**
     * Sends {@code UNION ALL SELECT} with 1, 2, 3... {@code NULL} columns until exactly one count
     * has answered differently from the others and a higher count has answered like them again.
     *
     * @return the count that stood out, or {@code null} if none did within the budget
     */
    private ColumnCount findColumnCount(
            ScanContext context,
            String originalValue,
            String closing,
            HttpMessage oneColumnMsg,
            String oneColumnPayload)
            throws IOException {
        HttpMessage baseline = context.getCachedBaseline();
        HttpMessage control = context.getCachedControl();
        String controlValue = originalValue + ScanContext.CONTROL_SUFFIX;
        if (control == null
                || comparator.matchesExactlyAfterStripping(
                        baseline,
                        originalValue,
                        originalValue,
                        control,
                        originalValue,
                        controlValue)) {
            // A page that answers a bad value like the original one shows no rejection for the
            // wrong counts to be compared with.
            return null;
        }
        List<HttpMessage> responses = new ArrayList<>();
        List<String> payloads = new ArrayList<>();
        boolean pendingConfirmation = false;

        for (int columns = 1; columns <= MAX_COLUMNS; columns++) {
            if (columns == 1 && oneColumnMsg != null) {
                responses.add(oneColumnMsg);
                payloads.add(oneColumnPayload);
            } else {
                // The last request goes to confirming a count that already stands out, and
                // otherwise stays with the canary, which is all that is left for a page that
                // answers every count alike.
                int reserve = pendingConfirmation ? 1 : 2;
                if (context.isStopped() || context.getRemainingBudget() < reserve) {
                    return null;
                }
                String payload = originalValue + closing + unionSelect(columns, false);
                HttpMessage msg = context.newMessage();
                context.setParam(msg, payload);
                context.sendAndReceive(msg);
                responses.add(msg);
                payloads.add(payload);
            }

            Map<Integer, List<Integer>> groups = groupAlike(responses, payloads, originalValue);
            if (groups.size() > 2) {
                // More than two different answers: the page reacts to the shape of the input
                // itself, not to whether the UNION parses.
                return null;
            }
            if (groups.size() < 2) {
                continue;
            }
            List<List<Integer>> members = new ArrayList<>(groups.values());
            List<Integer> odd = members.get(0).size() == 1 ? members.get(0) : members.get(1);
            List<Integer> alike = odd == members.get(0) ? members.get(1) : members.get(0);
            if (odd.size() != 1) {
                return null;
            }
            int oddIndex = odd.get(0);
            if (alike.size() < 2 || oddIndex == responses.size() - 1) {
                // Not confirmed yet: the odd count must be followed by a higher one answering like
                // the rest, so a page that only breaks past some length is not mistaken for it.
                pendingConfirmation = true;
                continue;
            }

            HttpMessage oddMsg = responses.get(oddIndex);
            String oddPayload = payloads.get(oddIndex);
            int rejected = alike.get(0);
            if (oddMsg.getResponseBody().toString().isBlank()
                    || oddMsg.getResponseHeader().getStatusCode()
                            != baseline.getResponseHeader().getStatusCode()
                    || !comparator.matchesExactlyAfterStripping(
                            control,
                            originalValue,
                            controlValue,
                            responses.get(rejected),
                            originalValue,
                            payloads.get(rejected))) {
                // The wrong counts must be rejected exactly like a bad value, and the odd one must
                // not be: a 200 with content, unlike the rejection.
                return null;
            }
            return new ColumnCount(oddIndex + 1, responses.size(), oddPayload, oddMsg);
        }
        return null;
    }

    /**
     * Groups the responses that are equal once each one's own payload is stripped, keyed by the
     * index of the first member, in order.
     */
    private Map<Integer, List<Integer>> groupAlike(
            List<HttpMessage> responses, List<String> payloads, String originalValue) {
        Map<Integer, List<Integer>> groups = new LinkedHashMap<>();
        for (int i = 0; i < responses.size(); i++) {
            Integer group = null;
            for (Integer first : groups.keySet()) {
                if (comparator.matchesExactlyAfterStripping(
                        responses.get(first),
                        originalValue,
                        payloads.get(first),
                        responses.get(i),
                        originalValue,
                        payloads.get(i))) {
                    group = first;
                    break;
                }
            }
            groups.computeIfAbsent(group == null ? i : group, k -> new ArrayList<>()).add(i);
        }
        return groups;
    }

    /**
     * Sends the payload with {@link #CANARY_PLACEHOLDER} replaced by a random canary and raises a
     * HIGH confidence alert if the response carries the canary's md5, which only the database can
     * have computed.
     *
     * @return true if an alert was raised
     */
    private static boolean raiseCanaryAlert(ScanContext context, String baselineBody, String probe)
            throws IOException {
        if (context.isStopped() || context.getRemainingBudget() < 1) {
            return false;
        }
        String canary = randomCanary();
        String token;
        try {
            token = md5Hex(canary);
        } catch (Exception e) {
            return false;
        }
        // Absent-from-baseline first, so a page that already contains the token cannot alert on it.
        if (baselineBody.contains(token)) {
            return false;
        }
        String payload = probe.replace(CANARY_PLACEHOLDER, canary);
        HttpMessage canaryMsg = context.newMessage();
        context.setParam(canaryMsg, payload);
        context.sendAndReceive(canaryMsg);

        // No strip: probe text and token live in disjoint alphabets, so any occurrence is computed
        // reflection, never echo.
        if (!canaryMsg.getResponseBody().toString().contains(token)) {
            return false;
        }
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

    /** Marks where {@link #raiseCanaryAlert} puts the canary. */
    private static final String CANARY_PLACEHOLDER = "@@CANARY@@";

    /**
     * {@code " UNION ALL SELECT NULL,...,NULL -- "} with the given number of columns; with {@code
     * canary}, the last column is {@code md5('<canary>')} instead.
     */
    private static String unionSelect(int columns, boolean canary) {
        StringBuilder select = new StringBuilder(" UNION ALL SELECT ");
        for (int i = 1; i <= columns; i++) {
            if (i > 1) {
                select.append(',');
            }
            select.append(canary && i == columns ? "md5('" + CANARY_PLACEHOLDER + "')" : "NULL");
        }
        return select.append(" -- ").toString();
    }

    /**
     * The 40018 appendages to send: only those with the learned closing when one is known,
     * otherwise all of them with the guessed closing's first.
     */
    private static List<String> appendagesFor(String learnedClosing, String guessedClosing) {
        if (learnedClosing != null) {
            return SQL_UNION_APPENDAGES.stream()
                    .filter(appendage -> isClosedBy(appendage, learnedClosing))
                    .toList();
        }
        List<String> ordered = new ArrayList<>();
        for (String appendage : SQL_UNION_APPENDAGES) {
            if (isClosedBy(appendage, guessedClosing)) {
                ordered.add(appendage);
            }
        }
        for (String appendage : SQL_UNION_APPENDAGES) {
            if (!isClosedBy(appendage, guessedClosing)) {
                ordered.add(appendage);
            }
        }
        return ordered;
    }

    /**
     * Whether a 40018 appendage opens with the given closing text, directly or after a {@code )}.
     */
    private static boolean isClosedBy(String appendage, String closing) {
        return appendage.startsWith(closing + " ") || appendage.startsWith(closing + ")");
    }

    /**
     * The hex of {@code md5(canary)}, which is what a UNION result interpolates when the database
     * evaluates the function: probe text carries the call, the response carries the hash.
     *
     * <p>Only the {@code md5()} name is tried (MySQL/Postgres); MSSQL needs {@code
     * HASHBYTES('MD5',...)} and other engines differ again. A miss there is FN-only, never FP: a
     * non-evaluated token simply doesn't reflect and the diff fallback below still runs. Ceiling is
     * one function name; upgrade is a per-{@link Dbms} function walk if the corpus ever shows a
     * silent-UNION row on a non-md5 engine.
     */
    static String md5Hex(String canary) throws Exception {
        byte[] digest =
                MessageDigest.getInstance("MD5").digest(canary.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(digest);
    }

    private static final SecureRandom CANARY_RANDOM = new SecureRandom();
    private static final HexFormat CANARY_HEX = HexFormat.of().withLowerCase();

    /**
     * A random hex canary with a fixed non-hex prefix, so the token (pure hex) can never coincide
     * with the canary itself and no baseline can already contain it except by astronomical
     * coincidence.
     */
    private static String randomCanary() {
        byte[] bytes = new byte[7];
        CANARY_RANDOM.nextBytes(bytes);
        return "zx" + CANARY_HEX.formatHex(bytes);
    }
}
