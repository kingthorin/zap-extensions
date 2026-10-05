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

/**
 * Analysis hints for a parameter, guiding payload selection and strategy ordering.
 *
 * <p>This used to carry three more flags — {@code isLikeContext}, {@code isOrderByContext} and
 * {@code isExpressionContext} — hard-coded {@code false}. They were removed rather than derived,
 * because nothing read them and nothing could derive them soundly: an arithmetic context is already
 * established where it matters, by {@code ExpressionBasedDetectionStrategy} parsing the value
 * itself, and a LIKE or ORDER BY context cannot be read off the request at all (rule 40018 does not
 * try either — it sends LIKE payloads unconditionally and enables ORDER BY by attack strength),
 * only by probing, which is what those two techniques already do.
 */
public class ParameterContext {

    public final boolean isNumericContext;
    public final boolean isStringLiteralContext;
    public final boolean baselineContainsErrorSignature;

    /**
     * Whether the baseline response's status is a redirect, a client error or a server error, so
     * the page is not a normal successful answer for this parameter to begin with.
     */
    public final boolean baselineIsNonNormalResponse;

    public final float dynamicContentVariance;

    public ParameterContext(
            boolean isNumericContext,
            boolean isStringLiteralContext,
            boolean baselineContainsErrorSignature,
            boolean baselineIsNonNormalResponse,
            float dynamicContentVariance) {
        this.isNumericContext = isNumericContext;
        this.isStringLiteralContext = isStringLiteralContext;
        this.baselineContainsErrorSignature = baselineContainsErrorSignature;
        this.baselineIsNonNormalResponse = baselineIsNonNormalResponse;
        this.dynamicContentVariance = dynamicContentVariance;
    }

    /** Estimates probability of success for each strategy, 0.0–1.0. */
    public float estimateProbabilityFor(String technique) {
        return switch (technique) {
            case "ERROR" -> isStringLiteralContext ? 0.85f : (isNumericContext ? 0.7f : 0.75f);
            case "BOOLEAN" -> 0.8f;
            case "EXPRESSION" -> isNumericContext ? 0.85f : 0.5f;
            case "ORDERBY" -> 0.6f; // no order-by context is known, so take the conservative prior
            case "UNION" -> 0.7f;
            default -> 0.5f;
        };
    }
}
