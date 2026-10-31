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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

/**
 * Scans very large real world responses (JSON, JS and HTML, 3 to 26 MB), to check that the scan
 * finishes in a reasonable time, and that a secret is found among the content without any false
 * positives.
 *
 * <p>The files are in the test resources, they are just data and are not part of the add-on:
 *
 * <ul>
 *   <li>{@code large-file.json}: https://github.com/json-iterator/test-data (large-file.json)
 *   <li>{@code monaco-editor.main.js}: monaco-editor 0.45.0, {@code min/vs/editor/editor.main.js}
 *   <li>{@code typescript.js}: typescript 5.3.3, {@code lib/typescript.js}
 *   <li>{@code whatwg-html-spec.html}: https://html.spec.whatwg.org/
 * </ul>
 */
class SecretsDisclosureScanRuleLargeResponsesUnitTest
        extends PassiveScannerTest<SecretsDisclosureScanRule> {

    private static final String RESOURCES =
            "/org/zaproxy/zap/extension/pscanrulesAlpha/secrets/large/";
    private static final String AWS_KEY = "AKIAQYLPMN5HFIQR7XYZ";

    /**
     * Generous, the slowest file takes about 6 seconds on a developer machine (these were measured,
     * 10 to 40 seconds before the scan was limited to the windows around the keywords).
     */
    private static final Duration MAX_DURATION = Duration.ofSeconds(30);

    @Override
    protected SecretsDisclosureScanRule createScanner() {
        return new SecretsDisclosureScanRule();
    }

    @ParameterizedTest
    @CsvSource({
        "large-file.json, application/json",
        "monaco-editor.main.js, application/javascript",
        "typescript.js, application/javascript",
        "whatwg-html-spec.html, text/html"
    })
    void shouldOnlyFindTheSecretAtTheEndOfLargeResponsesInReasonableTime(
            String file, String contentType) throws Exception {
        // Given
        byte[] content;
        try (InputStream is = getClass().getResourceAsStream(RESOURCES + file)) {
            content = is.readAllBytes();
        }
        byte[] secret = ("\n<p>" + AWS_KEY + "</p>").getBytes(StandardCharsets.UTF_8);
        byte[] body = new byte[content.length + secret.length];
        System.arraycopy(content, 0, body, 0, content.length);
        System.arraycopy(secret, 0, body, content.length, secret.length);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(new HttpRequestHeader("GET http://example.com/ HTTP/1.1"));
        msg.getResponseHeader().setStatusCode(200);
        msg.getResponseHeader().setHeader("Content-Type", contentType + "; charset=UTF-8");
        msg.setResponseBody(body);
        // When
        Assertions.assertTimeout(MAX_DURATION, () -> scanHttpResponseReceive(msg));
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), containsString(AWS_KEY));
    }
}
