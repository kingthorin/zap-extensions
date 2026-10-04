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
}
