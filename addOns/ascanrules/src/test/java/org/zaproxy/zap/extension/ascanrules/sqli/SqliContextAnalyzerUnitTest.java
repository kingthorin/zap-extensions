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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;

/** Pure-logic unit test for {@link SqliContextAnalyzer} -- no HTTP server needed. */
class SqliContextAnalyzerUnitTest {

    @Test
    void shouldInferNumericContextFromDigitsOnlyValue() throws Exception {
        // When
        ParameterContext context = SqliContextAnalyzer.analyze("42", new HttpMessage());
        // Then
        assertThat(context.isNumericContext, is(true));
        assertThat(context.isStringLiteralContext, is(false));
    }

    @Test
    void shouldInferStringContextFromNonNumericValue() throws Exception {
        // When
        ParameterContext context = SqliContextAnalyzer.analyze("jsmith", new HttpMessage());
        // Then
        assertThat(context.isNumericContext, is(false));
        assertThat(context.isStringLiteralContext, is(true));
    }
}
