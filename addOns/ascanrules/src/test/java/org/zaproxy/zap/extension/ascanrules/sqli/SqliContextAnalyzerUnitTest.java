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

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpMessage;

/** Pure-logic unit test for {@link SqliContextAnalyzer} -- no HTTP server needed. */
class SqliContextAnalyzerUnitTest {

    @ParameterizedTest
    @ValueSource(ints = {301, 302, 404, 403, 500})
    void shouldFlagBaselineThatIsNotANormalResponse(int status) throws Exception {
        // Given
        HttpMessage baseline = response(status, "some page");
        // When
        ParameterContext context = SqliContextAnalyzer.analyze("jsmith", baseline);
        // Then
        assertThat(context.baselineIsNonNormalResponse, is(true));
    }

    @ParameterizedTest
    @ValueSource(ints = {200, 201, 204})
    void shouldNotFlagNormalBaseline(int status) throws Exception {
        // Given
        HttpMessage baseline = response(status, "some page");
        // When
        ParameterContext context = SqliContextAnalyzer.analyze("jsmith", baseline);
        // Then
        assertThat(context.baselineIsNonNormalResponse, is(false));
    }

    private static HttpMessage response(int status, String body) throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setResponseHeader("HTTP/1.1 " + status + " Status\r\nContent-Type: text/html\r\n\r\n");
        msg.setResponseBody(body);
        return msg;
    }
}
