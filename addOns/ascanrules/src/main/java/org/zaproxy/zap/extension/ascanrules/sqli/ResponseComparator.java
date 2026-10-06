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
package org.zaproxy.zap.extension.ascanrules.sqli;

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.http.ComparableResponse;
import org.zaproxy.zap.extension.ascanrules.sqli.strategies.ResponseBodyUtils;

/**
 * Thin wrapper around commonlib's {@link ComparableResponse} fuzzy-diff heuristic (already used by
 * 40018 -- a known quantity, not extra risk to pull in).
 *
 * <p><strong>Caveat:</strong> this being a reasonable choice is proven against WAVSEP specifically.
 * WAVSEP's case labels (which pages are genuinely vulnerable) are solid ground truth verified
 * directly against the running app, but that doesn't make this comparison heuristic automatically
 * correct for every target. It's kept behind this one class, on the other side of the {@link
 * DetectionStrategy} seam, specifically so it can be swapped or rethought once validation moves on
 * to other test beds, without that decision leaking into the rest of the rule.
 */
public class ResponseComparator {

    /**
     * Similarity score (from {@link ComparableResponse#compareWith}) at or above which two
     * responses are considered the same outcome. 0 means very different, 1 means very similar.
     */
    private static final float SIMILARITY_THRESHOLD = 0.98f;

    private static final float FUZZY_TUNED_THRESHOLD = 0.97f;

    /**
     * Bodies larger than this are never templated: derivation and matching are linear in the body
     * size, but the matcher runs once per literal, so the size is capped and larger responses take
     * the exact-comparison path unchanged.
     */
    private static final int MAX_TEMPLATE_BODY_LENGTH = 8 * 1024 * 1024;

    /**
     * Upper bound on a response's lines before deriving gives up. Lines are the input to the
     * derivation, and a body of nothing but tiny lines would allocate more than it can afford to
     * hold. Pages past this take the exact-comparison path unchanged.
     */
    private static final int MAX_TEMPLATE_LINES = 10_000;

    /**
     * Upper bound on template literals. Matching makes one pass over the probe per literal, so the
     * literal count is what keeps a template from costing more than the comparison it replaces.
     * Past the cap: give up, exact path.
     */
    private static final int MAX_TEMPLATE_LITERALS = 32;

    /**
     * Whether a benign control request is indistinguishable from the baseline, i.e. the parameter
     * has no effect on the response at all — the case a blind technique cannot work on, because a
     * page that answers every value the same way also answers the true and the false condition the
     * same way.
     *
     * <p>Strict on purpose, and not the fuzzy {@link #isSimilar}: the question is whether the page
     * changed, not whether two responses are near each other. A redirect is the case that decides
     * it — a {@code 301} whose {@code Location} echoes the parameter value and one whose {@code
     * Location} echoes the control suffix are the same landing page, but they differ in their
     * headers, so both a fuzzy compare and {@link #matchesExactlyAfterStripping} (which compares
     * {@code Location} verbatim) call them different. Same status, same {@code Location} with the
     * value stripped, same body with the value stripped: match.
     *
     * @param baseline the response to the original value
     * @param originalValue the original parameter value
     * @param control the response to the benign control value
     * @param controlValue the benign control value sent
     * @return true if the control response is the same outcome as the baseline
     */
    public boolean isIndistinguishableFromBenignControl(
            HttpMessage baseline, String originalValue, HttpMessage control, String controlValue) {
        int status = baseline.getResponseHeader().getStatusCode();
        if (status != control.getResponseHeader().getStatusCode()) {
            return false;
        }

        // A redirect's Location echoes the value sent, so it is normalised the way the body is
        // rather than compared verbatim -- which is what makes the same landing page behind two
        // different URLs read as one outcome here and as two in matchesExactlyAfterStripping.
        if (HttpStatusCode.isRedirection(status)) {
            String location =
                    ResponseBodyUtils.stripAllEncodedForms(
                            baseline.getResponseHeader().getHeader("Location"),
                            originalValue,
                            controlValue);
            String controlLocation =
                    ResponseBodyUtils.stripAllEncodedForms(
                            control.getResponseHeader().getHeader("Location"),
                            originalValue,
                            controlValue);
            if (!equals(location, controlLocation)) {
                return false;
            }
        }

        return bodiesMatchAfterStripping(
                baseline.getResponseBody().toString(),
                originalValue,
                controlValue,
                control.getResponseBody().toString(),
                originalValue,
                controlValue);
    }

    /**
     * Whether two response bodies are the same page: byte-identical, or equal once every form of
     * the value sent is stripped from each side.
     *
     * <p>Byte-identical is checked first on purpose: stripping can manufacture a phantom difference
     * when the response legitimately contains the value sent (e.g. a page that echoes the
     * confirmation expression back as content).
     */
    private static boolean bodiesMatchAfterStripping(
            String aBody,
            String aOriginalValue,
            String aValueSent,
            String bBody,
            String bOriginalValue,
            String bValueSent) {
        if (aBody.equals(bBody)) {
            return true;
        }

        return ResponseBodyUtils.stripAllEncodedForms(aBody, aOriginalValue, aValueSent)
                .equals(ResponseBodyUtils.stripAllEncodedForms(bBody, bOriginalValue, bValueSent));
    }

    /**
     * Whether {@code a} and {@code b} represent essentially the same response.
     *
     * <p>A fuzzy similarity over the whole response, so a header that echoes the value sent counts
     * against it — fine for "are these the same outcome", wrong for "does this parameter matter",
     * which is {@link #isIndistinguishableFromBenignControl}.
     */
    public boolean isSimilar(HttpMessage a, String aValue, HttpMessage b, String bValue) {
        return similarity(a, aValue, b, bValue) >= SIMILARITY_THRESHOLD;
    }

    /** Whether {@code a} and {@code b} represent meaningfully different responses. */
    public boolean isDifferent(HttpMessage a, String aValue, HttpMessage b, String bValue) {
        return !isSimilar(a, aValue, b, bValue);
    }

    /**
     * Fuzzy similarity with tuned heuristics: creates two ComparableResponse objects, tunes their
     * weights based on each other, then compares them. More adaptive than strict matching but
     * retains fidelity through weight tuning.
     */
    public boolean isSimilarTuned(HttpMessage a, String aValue, HttpMessage b, String bValue) {
        return similarityTuned(a, aValue, b, bValue) >= FUZZY_TUNED_THRESHOLD;
    }

    /** Negation of isSimilarTuned for boolean logic. */
    public boolean isDifferentTuned(HttpMessage a, String aValue, HttpMessage b, String bValue) {
        return !isSimilarTuned(a, aValue, b, bValue);
    }

    /**
     * Compares two responses for exact equality after stripping the original value and the value
     * sent in all their encoded forms. Status codes must match; bodies are stripped of the patterns
     * and compared with binary equality. For redirect responses (3xx), also checks that Location
     * headers match (mirroring baseline's locationHeaderHeuristic).
     *
     * @param a the first message
     * @param aOriginalValue the original parameter value for message a
     * @param aValueSent the value actually sent in the request for message a
     * @param b the second message
     * @param bOriginalValue the original parameter value for message b
     * @param bValueSent the value actually sent in the request for message b
     * @return true if status codes are equal, Location headers match (if both are redirects), and
     *     response bodies match after stripping, false otherwise
     */
    public boolean matchesExactlyAfterStripping(
            HttpMessage a,
            String aOriginalValue,
            String aValueSent,
            HttpMessage b,
            String bOriginalValue,
            String bValueSent) {
        int statusA = a.getResponseHeader().getStatusCode();
        int statusB = b.getResponseHeader().getStatusCode();
        if (statusA != statusB) {
            return false;
        }

        // For redirects (3xx), also check Location header equality
        if (statusA >= 300 && statusA < 400) {
            String locationA = a.getResponseHeader().getHeader("Location");
            String locationB = b.getResponseHeader().getHeader("Location");
            if (!equals(locationA, locationB)) {
                return false;
            }
        }

        // Bodies are compared byte-identical first, then with the values stripped: see
        // bodiesMatchAfterStripping.
        return bodiesMatchAfterStripping(
                a.getResponseBody().toString(),
                aOriginalValue,
                aValueSent,
                b.getResponseBody().toString(),
                bOriginalValue,
                bValueSent);
    }

    private static boolean equals(String a, String b) {
        return (a == null && b == null) || (a != null && a.equals(b));
    }

    /**
     * Whether the difference between a baseline response and a probe response is explained by the
     * probe being answered with an error page, rather than by the probe's value having changed the
     * outcome of the query.
     *
     * <p>Excludes the reported false positives:
     *
     * <ul>
     *   <li>zaproxy/zaproxy#8652: the false condition of a boolean pair answered with {@code 429
     *       Too Many Requests} while the original value and the true condition were both answered
     *       {@code 200}.
     *   <li>zaproxy/zaproxy#8653: a payload rejected with {@code 403 Forbidden} by a WAF where the
     *       original value returned a static asset with {@code 200}.
     *   <li>zaproxy/zaproxy#8651 and zaproxy/zaproxy#9289: a numeric parameter cast to an integer,
     *       where the confirming expression resolved to a non-existing id and so was answered with
     *       a {@code 404} error page.
     *   <li>zaproxy/zaproxy#8525: a slow handler answering the false condition with {@code 500}.
     * </ul>
     *
     * <p>Directional on purpose: when the baseline is itself an error response, a difference
     * between two error responses is still evidence.
     *
     * @param baseline the baseline message
     * @param probe the message sent with the probe value
     * @return true if the probe's error status explains the difference
     */
    public boolean isDifferenceExplainedByErrorStatus(HttpMessage baseline, HttpMessage probe) {
        return !isErrorStatus(baseline.getResponseHeader().getStatusCode())
                && isErrorStatus(probe.getResponseHeader().getStatusCode());
    }

    private static boolean isErrorStatus(int statusCode) {
        return HttpStatusCode.isClientError(statusCode) || HttpStatusCode.isServerError(statusCode);
    }

    private float similarity(HttpMessage a, String aValue, HttpMessage b, String bValue) {
        ComparableResponse responseA = new ComparableResponse(a, aValue);
        ComparableResponse responseB = new ComparableResponse(b, bValue);
        return responseA.compareWith(responseB);
    }

    private float similarityTuned(HttpMessage a, String aValue, HttpMessage b, String bValue) {
        ComparableResponse responseA = new ComparableResponse(a, aValue);
        ComparableResponse responseB = new ComparableResponse(b, bValue);
        // Tune weights based on each other for more adaptive comparison
        responseA.tuneHeuristicsWithResponse(responseB);
        responseB.tuneHeuristicsWithResponse(responseA);
        return responseA.compareWith(responseB);
    }

    // -- Volatile content: learn what moves between two renders of the same request, then compare
    // the rest exactly. A scalar similarity score cannot say *where* a page is noisy; a template
    // can, which is what keeps the differential's precision (and its false-positive safety) on a
    // page whose body changes on every request. ---

    /**
     * A page template learned from two renders of the same request: the spans that stayed stable,
     * in order, with an implicit wildcard between them (and before the first / after the last when
     * that end of the body moved). Matching is an ordered-containment check, not a regular
     * expression: linear in the probe, no compilation, no backtracking.
     *
     * @param literals the stable spans of the body, in order
     * @param startAnchored whether the first literal begins the body (otherwise a wildcard precedes
     *     it)
     * @param endAnchored whether the last literal ends the body (otherwise a wildcard follows it)
     */
    public record VolatileTemplate(
            List<String> literals, boolean startAnchored, boolean endAnchored) {
        public VolatileTemplate {
            literals = List.copyOf(literals);
        }
    }

    /**
     * Learns which parts of a page move between two identical requests, so a comparison on a
     * volatile page can ignore the moving parts and hold everything else to the same exact standard
     * as a still page.
     *
     * <p>Call this only after {@link #matchesExactlyAfterStripping} failed with a matching status:
     * that failure on a volatile page is the signature this learns. Every give-up returns {@code
     * null} and leaves the caller on today's exact path — an untemplatable page is never guessed
     * at:
     *
     * <ul>
     *   <li>a body over {@value #MAX_TEMPLATE_BODY_LENGTH} characters or over {@value
     *       #MAX_TEMPLATE_LINES} lines;
     *   <li>the two bodies already equal after stripping (the exact failure came from something a
     *       body template cannot speak to, such as a redirect's {@code Location});
     *   <li>lines added or removed between the two renders (unalignable without a real diff, and
     *       guessing the alignment risks hiding a real difference);
     *   <li>no stable span at all, or more than {@value #MAX_TEMPLATE_LITERALS} of them.
     * </ul>
     *
     * <p>Known ceiling, deliberate: content that varies *within* a learned wildcard is invisible to
     * the template. That loses detections (a miss), never invents them — a benign probe's stable
     * content still has to match for the true half of the differential, and the false half has to
     * leave it.
     *
     * @param baseline the baseline message
     * @param baselineOriginalValue the original parameter value for the baseline
     * @param baselineValueSent the value actually sent in the baseline request
     * @param replay the same request sent a second time ({@link ScanContext#getRepeatedBaseline()})
     * @param replayOriginalValue the original parameter value for the replay
     * @param replayValueSent the value actually sent in the replay request
     * @return the learned template, or {@code null} if the page cannot be templated safely
     */
    public VolatileTemplate deriveVolatileTemplate(
            HttpMessage baseline,
            String baselineOriginalValue,
            String baselineValueSent,
            HttpMessage replay,
            String replayOriginalValue,
            String replayValueSent) {
        String baselineBody = baseline.getResponseBody().toString();
        String replayBody = replay.getResponseBody().toString();
        if (baselineBody.length() > MAX_TEMPLATE_BODY_LENGTH
                || replayBody.length() > MAX_TEMPLATE_BODY_LENGTH) {
            return null;
        }

        String stable =
                ResponseBodyUtils.stripAllEncodedForms(
                        baselineBody, baselineOriginalValue, baselineValueSent);
        String moving =
                ResponseBodyUtils.stripAllEncodedForms(
                        replayBody, replayOriginalValue, replayValueSent);
        if (stable.equals(moving)) {
            return null;
        }
        if (countLines(stable) > MAX_TEMPLATE_LINES || countLines(moving) > MAX_TEMPLATE_LINES) {
            return null;
        }

        String[] left = stable.split("\n", -1);
        String[] right = moving.split("\n", -1);
        if (left.length != right.length) {
            return null;
        }

        List<String> literals = new ArrayList<>();
        StringBuilder stableRun = new StringBuilder();
        boolean startAnchored = false;
        boolean endAnchored = false;
        for (int i = 0; i < left.length; i++) {
            if (left[i].equals(right[i])) {
                if (stableRun.length() > 0) {
                    stableRun.append('\n');
                }
                stableRun.append(left[i]);
                if (i == 0) {
                    startAnchored = true;
                }
                endAnchored = true;
                continue;
            }

            if (stableRun.length() > 0) {
                literals.add(stableRun.toString());
                stableRun.setLength(0);
            }
            int[] span = stableSpan(left[i], right[i]);
            int prefix = span[0];
            int suffix = span[1];
            if (i == 0) {
                startAnchored = prefix > 0;
            }
            if (prefix > 0) {
                literals.add(left[i].substring(0, prefix));
            }
            if (suffix > 0) {
                literals.add(left[i].substring(left[i].length() - suffix));
            }
            endAnchored = suffix > 0;
        }
        if (stableRun.length() > 0) {
            literals.add(stableRun.toString());
        }

        if (literals.isEmpty() || literals.size() > MAX_TEMPLATE_LITERALS) {
            return null;
        }
        return new VolatileTemplate(literals, startAnchored, endAnchored);
    }

    /**
     * Whether a response fits a template learned from two renders of the baseline: same status (and
     * for redirects, the same {@code Location}, exactly as {@link #matchesExactlyAfterStripping}
     * requires), and stable content that the template's literals cover in order — the learned
     * wildcards absorb whatever moves between requests.
     *
     * @param template the template learned for this parameter
     * @param a the baseline message (identity side of the template)
     * @param aOriginalValue the original parameter value for {@code a}
     * @param aValueSent the value actually sent in {@code a}'s request
     * @param b the probe message
     * @param bOriginalValue the original parameter value for {@code b}
     * @param bValueSent the value actually sent in {@code b}'s request
     * @return true if the probe matches the template
     */
    public boolean matchesTemplate(
            VolatileTemplate template,
            HttpMessage a,
            String aOriginalValue,
            String aValueSent,
            HttpMessage b,
            String bOriginalValue,
            String bValueSent) {
        int statusA = a.getResponseHeader().getStatusCode();
        int statusB = b.getResponseHeader().getStatusCode();
        if (statusA != statusB) {
            return false;
        }
        if (statusA >= 300 && statusA < 400) {
            String locationA = a.getResponseHeader().getHeader("Location");
            String locationB = b.getResponseHeader().getHeader("Location");
            if (!equals(locationA, locationB)) {
                return false;
            }
        }

        String body =
                ResponseBodyUtils.stripAllEncodedForms(
                        b.getResponseBody().toString(), bOriginalValue, bValueSent);
        if (body.length() > MAX_TEMPLATE_BODY_LENGTH) {
            return false;
        }

        List<String> literals = template.literals();
        int pos = 0;
        for (int i = 0; i < literals.size(); i++) {
            String literal = literals.get(i);
            boolean atStart = i == 0 && template.startAnchored();
            boolean atEnd = i == literals.size() - 1 && template.endAnchored();
            if (atStart && atEnd) {
                return body.startsWith(literal) && body.endsWith(literal);
            }
            if (atStart) {
                if (!body.startsWith(literal)) {
                    return false;
                }
                pos = literal.length();
            } else if (atEnd) {
                return body.endsWith(literal) && body.length() - literal.length() >= pos;
            } else {
                int index = body.indexOf(literal, pos);
                if (index < 0) {
                    return false;
                }
                pos = index + literal.length();
            }
        }
        return true;
    }

    /**
     * The stable span at the start and at the end of a differing line pair, snapped to token
     * boundaries: a span that ends mid-token is trimmed back to the last delimiter, so a
     * coincidence between two samples (the leading digit two counters happen to share) is not baked
     * into the template as if it were stable content. When a side has no delimiter at all the
     * partial token is kept — the alternative is giving up on delimiter-less bodies entirely.
     *
     * @param left the baseline's line
     * @param right the replay's line
     * @return {prefix length, suffix length} into {@code left}, each possibly zero
     */
    private static int[] stableSpan(String left, String right) {
        int max = Math.min(left.length(), right.length());
        int prefix = 0;
        while (prefix < max && left.charAt(prefix) == right.charAt(prefix)) {
            prefix++;
        }
        int suffix = 0;
        while (suffix < max - prefix
                && left.charAt(left.length() - 1 - suffix)
                        == right.charAt(right.length() - 1 - suffix)) {
            suffix++;
        }

        if (prefix > 0 && isTokenChar(left.charAt(prefix - 1))) {
            for (int i = prefix - 1; i >= 0; i--) {
                if (!isTokenChar(left.charAt(i))) {
                    prefix = i + 1;
                    break;
                }
            }
        }
        if (suffix > 0 && isTokenChar(left.charAt(left.length() - suffix))) {
            for (int i = left.length() - suffix; i < left.length(); i++) {
                if (!isTokenChar(left.charAt(i))) {
                    suffix = left.length() - i;
                    break;
                }
            }
        }
        return new int[] {prefix, suffix};
    }

    private static boolean isTokenChar(char c) {
        return Character.isLetterOrDigit(c);
    }

    private static int countLines(String body) {
        int lines = 1;
        for (int i = 0; i < body.length(); i++) {
            if (body.charAt(i) == '\n') {
                lines++;
            }
        }
        return lines;
    }
}
