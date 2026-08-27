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

/** Analysis hints for a parameter, guiding payload selection and strategy ordering. */
public class ParameterContext {

    public final boolean isNumericContext;
    public final boolean isStringLiteralContext;
    public final boolean isLikeContext;
    public final boolean isOrderByContext;
    public final boolean isExpressionContext;
    public final boolean baselineContainsErrorSignature;
    public final float dynamicContentVariance;

    public ParameterContext(
            boolean isNumericContext,
            boolean isStringLiteralContext,
            boolean isLikeContext,
            boolean isOrderByContext,
            boolean isExpressionContext,
            boolean baselineContainsErrorSignature,
            float dynamicContentVariance) {
        this.isNumericContext = isNumericContext;
        this.isStringLiteralContext = isStringLiteralContext;
        this.isLikeContext = isLikeContext;
        this.isOrderByContext = isOrderByContext;
        this.isExpressionContext = isExpressionContext;
        this.baselineContainsErrorSignature = baselineContainsErrorSignature;
        this.dynamicContentVariance = dynamicContentVariance;
    }

    /** Estimates probability of success for each strategy, 0.0–1.0. */
    public float estimateProbabilityFor(String technique) {
        return switch (technique) {
            case "ERROR" -> isStringLiteralContext ? 0.85f : (isNumericContext ? 0.7f : 0.75f);
            case "BOOLEAN" -> 0.8f;
            case "EXPRESSION" -> isNumericContext ? 0.85f : 0.5f;
            case "ORDERBY" -> isOrderByContext ? 0.8f : 0.6f;
            case "UNION" -> 0.7f;
            default -> 0.5f;
        };
    }
}
