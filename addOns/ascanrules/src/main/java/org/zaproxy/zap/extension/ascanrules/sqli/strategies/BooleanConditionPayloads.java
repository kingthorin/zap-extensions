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
 * Boolean condition payloads for SQL injection detection. Each pair contains an AND_TRUE and
 * AND_FALSE condition to drive a restrict-then-verify differential: AND_TRUE should match the
 * baseline response; AND_FALSE should differ from it.
 *
 * <p>OR-based conditions are intentionally absent. An {@code OR <true expression>} in a WHERE
 * clause acts as a universal tautology: on a vulnerable SELECT it returns every row in the
 * table (potential DoS), and on a vulnerable DELETE/UPDATE it affects every row (catastrophic
 * data loss). AND conditions are safe by contrast — they restrict, never expand, the matched
 * row set beyond what the original query already returned.
 *
 * <p>The 9 pairs cover string contexts (single/double quote, with/without trailing comment),
 * numeric contexts, and varied constructs (arithmetic comparison, BETWEEN, LIKE, IS NULL) for
 * broad DBMS portability.
 */
public class BooleanConditionPayloads {

    public record Condition(String andTrue, String andFalse) {}

    /** 9 boolean condition pairs for AND_TRUE / AND_FALSE differential detection. */
    public static final List<Condition> CONDITIONS =
            List.of(
                    // String context: single quote + arithmetic comparison with comment
                    new Condition("' AND 2>1 -- ", "' AND 2>3 -- "),
                    // String context: double quote + arithmetic comparison with comment
                    new Condition("\" AND 2>1 -- ", "\" AND 2>3 -- "),
                    // Numeric context: arithmetic comparison with comment
                    new Condition(" AND 2>1 -- ", " AND 2>3 -- "),
                    // String context: single quote + BETWEEN without comment
                    new Condition("' AND 3 BETWEEN 2 AND 4", "' AND 3 BETWEEN 5 AND 6"),
                    // String context: double quote + BETWEEN without comment
                    new Condition("\" AND 3 BETWEEN 2 AND 4", "\" AND 3 BETWEEN 5 AND 6"),
                    // Numeric context: arithmetic comparison without comment
                    new Condition(" AND 2>1", " AND 2>3"),
                    // String context: single quote + LIKE with non-obvious prefix operand
                    new Condition("' AND 'abc' LIKE 'a%", "' AND 'abc' LIKE 'z%"),
                    // Numeric context: LIKE with string literal
                    new Condition("1 AND 'abc' LIKE 'a%", "1 AND 'abc' LIKE 'z%"),
                    // String context: single quote + IS NULL / IS NOT NULL with comment
                    new Condition("' AND NULL IS NULL -- ", "' AND NULL IS NOT NULL -- "));

    private BooleanConditionPayloads() {}
}
