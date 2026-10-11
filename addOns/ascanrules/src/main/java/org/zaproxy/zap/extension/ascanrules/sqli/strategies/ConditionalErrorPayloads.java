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

import java.util.List;

/**
 * Conditional-error payload pairs for blind SQL injection detection: an AND_FALSE probe that must
 * answer normally, and an AND_TRUE probe of the same shape that must raise a database error when
 * the injected condition is evaluated.
 *
 * <p>Each pair wraps a {@code CASE WHEN <cond> THEN <error> ELSE <benign> END} so the ONLY
 * difference between the two probes is the injected condition ({@code 1=2} vs {@code 1=1});
 * everything else -- quote balance, comment, surrounding structure -- is identical. That is what
 * makes the pair a discriminator: on a vulnerable query the TRUE probe errors and the FALSE probe
 * does not, while on a page that errors on any metacharacter (input validation) BOTH error, so the
 * pair fails closed.
 *
 * <p>The error branch is a divide-by-zero ({@code 1/0}) -- a portable arithmetic error every major
 * engine raises, needing no engine-specific function. No SLEEP/WAITFOR/delay form is used anywhere:
 * the signal is error presence, never elapsed time, so this technique stays in the non-timing rules
 * and the blind stacked-query delay work is left to the timing-based rules.
 *
 * <p>AND-based, matching {@link BooleanConditionPayloads}: an OR tautology would widen a vulnerable
 * SELECT/DELETE/UPDATE, while AND only restricts, so these probes never expand the matched row set.
 */
public class ConditionalErrorPayloads {

    public record Condition(String andFalse, String andTrue) {}

    /**
     * Conditional-error pairs, cheapest/most-portable first. String contexts are covered first (the
     * common case), then a numeric/quote-free shape. Each FALSE/TRUE pair differs only in the CASE
     * condition.
     */
    public static final List<Condition> CONDITIONS =
            List.of(
                    // String context, single quote, trailing comment: 1/0 errors on TRUE, 'a' is a
                    // harmless literal on FALSE.
                    new Condition(
                            "' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a' -- ",
                            "' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a' -- "),
                    // Numeric/quote-free context: no leading quote, no comment needed.
                    new Condition(
                            " AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 1 END)=1",
                            " AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)=1"));

    private ConditionalErrorPayloads() {}
}
