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
 * <p>Two kinds of hint live here: what the value and the parameter name suggest before anything is
 * sent ({@link #getValueShape()}, {@link #isOrderByHint()}), and the SQL context a probe has
 * actually shown ({@link #getLearnedClosing()}), which is evidence rather than a guess and so wins
 * over the value shape wherever both are available.
 */
public class ParameterContext {

    /** What the original value looks like, independent of how the query quotes it. */
    public enum ValueShape {
        /** Digits only, typically compared unquoted. */
        NUMERIC,
        /** An ISO-style date, which applications both quote and leave unquoted. */
        DATE,
        /** A bare word such as a column name, a sort key or a username. */
        IDENTIFIER,
        /** Anything else. */
        TEXT
    }

    public final boolean isNumericContext;
    public final boolean isStringLiteralContext;

    private final ValueShape valueShape;
    private final boolean orderByHint;
    private String learnedClosing;

    public ParameterContext(
            boolean isNumericContext,
            boolean isStringLiteralContext,
            ValueShape valueShape,
            boolean orderByHint) {
        this.isNumericContext = isNumericContext;
        this.isStringLiteralContext = isStringLiteralContext;
        this.valueShape = valueShape;
        this.orderByHint = orderByHint;
    }

    public ValueShape getValueShape() {
        return valueShape;
    }

    /**
     * Whether the parameter name or value suggests it is spliced into an {@code ORDER BY} clause
     * ({@code sort}, {@code orderby}, a trailing {@code ASC}/{@code DESC}).
     */
    public boolean isOrderByHint() {
        return orderByHint;
    }

    /**
     * Records the text that closes the value's SQL context, as shown by a probe that extended the
     * query with it and got the baseline back: {@code ""} for an unquoted value, {@code "'"} or
     * {@code "\""} for a quoted one. The first one learned is kept.
     *
     * @param closing the closing text the probe used
     */
    public void learnClosing(String closing) {
        if (learnedClosing == null) {
            learnedClosing = closing;
        }
    }

    /**
     * The closing text learned by {@link #learnClosing(String)}, or {@code null} if no probe has
     * shown it yet.
     */
    public String getLearnedClosing() {
        return learnedClosing;
    }

    /**
     * The closing text to try when none has been learned: unquoted for values that are usually
     * compared or ordered unquoted (numbers, dates, sort keys), a single quote otherwise.
     */
    public String getGuessedClosing() {
        if (learnedClosing != null) {
            return learnedClosing;
        }
        return switch (valueShape) {
            case NUMERIC, DATE -> "";
            case IDENTIFIER -> orderByHint ? "" : "'";
            case TEXT -> "'";
        };
    }

    /** Estimates probability of success for each strategy, 0.0–1.0. */
    public float estimateProbabilityFor(String technique) {
        return switch (technique) {
            case "ERROR" -> isStringLiteralContext ? 0.85f : (isNumericContext ? 0.7f : 0.75f);
            case "CONDERROR" -> isStringLiteralContext ? 0.8f : (isNumericContext ? 0.7f : 0.75f);
            case "BOOLEAN" -> 0.8f;
            case "EXPRESSION" -> isNumericContext ? 0.85f : 0.5f;
            // A sort parameter is ORDER BY's own context, and the other differential techniques
            // cannot narrow an ORDER BY clause, so it goes ahead of them.
            case "ORDERBY" -> orderByHint ? 0.9f : 0.6f;
            case "UNION" -> 0.7f;
            default -> 0.5f;
        };
    }
}
