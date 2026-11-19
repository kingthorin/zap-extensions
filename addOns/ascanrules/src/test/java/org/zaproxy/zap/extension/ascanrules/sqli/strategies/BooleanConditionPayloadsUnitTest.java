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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/** Unit test for {@link BooleanConditionPayloads}. */
class BooleanConditionPayloadsUnitTest {

    /**
     * Payloads are appended to the original value, so one that starts with a digit would turn "5"
     * into "51 AND ..." and the true probe could never match.
     */
    @Test
    void shouldOnlyAppendToTheOriginalValue() {
        // When
        boolean anyStartsWithDigit =
                Stream.concat(
                                BooleanConditionPayloads.CONDITIONS.stream(),
                                BooleanConditionPayloads.LIKE_CONDITIONS.stream())
                        .flatMap(c -> Stream.of(c.andTrue(), c.andFalse()))
                        .anyMatch(p -> !p.isEmpty() && Character.isDigit(p.charAt(0)));
        // Then
        assertThat(anyStartsWithDigit, is(false));
    }
}
