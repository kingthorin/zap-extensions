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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.pscanrulesAlpha.secrets.GitleaksConfigLoader;

class SecretsDisclosureScanRuleUnitTest extends PassiveScannerTest<SecretsDisclosureScanRule> {

    // Matches aws-access-token, and is not allowlisted (does not end with EXAMPLE).
    private static final String AWS_KEY = "AKIAQYLPMN5HFIQR7XYZ";

    @Override
    protected SecretsDisclosureScanRule createScanner() {
        return new SecretsDisclosureScanRule();
    }

    private void useFixtureConfig() throws Exception {
        try (InputStream is =
                getClass()
                        .getResourceAsStream(
                                "/org/zaproxy/zap/extension/pscanrulesAlpha/secrets/test-gitleaks.toml")) {
            rule = new SecretsDisclosureScanRule(GitleaksConfigLoader.load(is));
        }
        rule.setPassiveScanActions(actions);
        rule.setHelper(passiveScanData);
    }

    @Test
    void shouldHaveExpectedPluginId() {
        assertThat(rule.getPluginId(), is(equalTo(10005)));
    }

    @Test
    void shouldRaiseAlertWhenSecretInBody() throws Exception {
        // Given
        HttpMessage msg = createMessage("<p>" + AWS_KEY + "</p>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getPluginId(), is(equalTo(10005)));
        assertThat(alert.getName(), is(equalTo("Secrets Disclosure")));
        assertThat(rule.getName(), is(equalTo("Secrets Disclosure (Powered by Gitleaks)")));
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alert.getEvidence(), containsString(AWS_KEY));
        assertThat(alert.getOtherInfo(), containsString("aws-access-token"));
    }

    @Test
    void shouldRaiseAlertWhenCaseMappingWouldChangeTheBodyLength() throws Exception {
        // Given: U+0130 has a lower case form of 2 chars with String#toLowerCase.
        HttpMessage msg = createMessage("\u0130 \u0130 <p>" + AWS_KEY + "</p>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), containsString(AWS_KEY));
    }

    @Test
    void shouldNotRaiseAlertWhenBodyIsClean() throws Exception {
        // Given
        HttpMessage msg = createMessage("<html><body>Hello world</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotRaiseAlertWhenSecretIsAllowlisted() throws Exception {
        // Given
        HttpMessage msg = createMessage("key=AKIAQYLPMN5HFIQR7EXAMPLE");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldRaiseAlertUsingFixtureRule() throws Exception {
        // Given
        useFixtureConfig();
        HttpMessage msg = createMessage("a tok_k3j9x0q8w7z1 b");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getOtherInfo(), containsString("test-token"));
    }

    @Test
    void shouldNotRaiseAlertWhenKeywordMissing() throws Exception {
        // Given: matches the regex only if the keyword is present, regex itself needs "tok_".
        useFixtureConfig();
        HttpMessage msg = createMessage("a TOK-k3j9x0q8w7z1 b");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotRaiseAlertWhenRuleStopwordMatches() throws Exception {
        // Given
        useFixtureConfig();
        HttpMessage msg = createMessage("a tok_sample000000 b");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotRaiseAlertWhenGlobalStopwordMatches() throws Exception {
        // Given
        useFixtureConfig();
        HttpMessage msg = createMessage("a tok_globalstop0 b");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotRaiseAlertWhenEntropyTooLow() throws Exception {
        // Given
        useFixtureConfig();
        HttpMessage msg = createMessage("a tok_aaaaaaaaaaaa b");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @CsvSource({
        "HIGH, /vendor/app.js, 0",
        "HIGH, /rulepath/app.js, 0",
        "MEDIUM, /rulepath/app.js, 1",
        "HIGH, /app/app.js, 1",
        "MEDIUM, /vendor/app.js, 1",
        "LOW, /vendor/app.js, 1"
    })
    void shouldUseAllowlistPathsOnlyAtHighThreshold(
            AlertThreshold threshold, String path, int expectedAlerts) throws Exception {
        // Given
        useFixtureConfig();
        rule.setAlertThreshold(threshold);
        HttpMessage msg = createMessage("http://example.com" + path, "a tok_k3j9x0q8w7z1 b");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(expectedAlerts));
    }

    @ParameterizedTest
    @CsvSource({"image/png", "font/woff2", "application/font-woff"})
    void shouldIgnoreResponsesWithNonTextContentType(String contentType) throws Exception {
        // Given
        HttpMessage msg = createMessage("<p>" + AWS_KEY + "</p>");
        msg.getResponseHeader().setHeader("Content-Type", contentType);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldLoadBundledConfigOnlyOnce() {
        // Given / When
        SecretsDisclosureScanRule other = new SecretsDisclosureScanRule();
        // Then
        assertThat(rule.config, is(not(nullValue())));
        assertThat(rule.config.rules(), is(not(empty())));
        assertThat(other.config, is(sameInstance(rule.config)));
    }

    @Test
    void shouldScanUtf8ResponseLabelledAsIso88591() throws Exception {
        // Given: the UTF-8 bytes of the curly quotes are decoded as C1 control characters.
        HttpMessage msg = createMessage("");
        msg.getResponseHeader().setHeader("Content-Type", "text/html; charset=ISO-8859-1");
        msg.setResponseBody(
                ("<p>\u201cquoted\u201d caf\u00e9 " + AWS_KEY + "</p>")
                        .getBytes(StandardCharsets.UTF_8));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldIgnoreBinaryRequests() throws Exception {
        // Given
        HttpMessage msg =
                createRequest(
                        "POST",
                        "http://example.com/",
                        "multipart/form-data; boundary=x",
                        "--x\r\n\u0000\u0001\r\n" + AWS_KEY + "\r\n--x--");
        // When
        scanHttpRequestSend(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\u0000", "\u0001", "\u0008", "\u001b"})
    void shouldIgnoreBinaryResponses(String controlChar) throws Exception {
        // Given
        HttpMessage msg = createMessage(controlChar + "<p>" + AWS_KEY + "</p>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\u007f", "\u0085", "\u0093", "\u009f", "\t", "\r\n", "\u001f"})
    void shouldScanResponsesWithCharsMistakenForBinaryByCommonlib(String chars) throws Exception {
        // Given: e.g. Windows-1252 content (curly quotes) labelled as ISO-8859-1.
        HttpMessage msg = createMessage(chars + "<p>" + AWS_KEY + "</p>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @ParameterizedTest
    @CsvSource({"LOW, 1", "MEDIUM, 0", "HIGH, 0"})
    void shouldOnlyUseGenericRuleAtLowThreshold(AlertThreshold threshold, int expectedAlerts)
            throws Exception {
        // Given
        rule.setAlertThreshold(threshold);
        HttpMessage msg = createMessage("secret_value = \"Zk8dQ3vN7pLw2XrT9mBc\"");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(expectedAlerts));
        if (expectedAlerts > 0) {
            assertThat(alertsRaised.get(0).getOtherInfo(), containsString("generic-api-key"));
        }
    }

    @ParameterizedTest
    @CsvSource({"0, 1", "10, 1", "11, 0", "500, 0"})
    void shouldOnlyIgnoreResponsesWithMoreThanOnePercentControlChars(
            int controlChars, int expectedAlerts) throws Exception {
        // Given: 1000 characters, 10 are 1%.
        String start = "<p>" + AWS_KEY + "</p>";
        String body =
                start
                        + "x".repeat(1000 - controlChars - start.length())
                        + "\u0001".repeat(controlChars);
        HttpMessage msg = createMessage(body);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(body.length(), is(equalTo(1000)));
        assertThat(alertsRaised, hasSize(expectedAlerts));
    }

    @Test
    void shouldScanLargeResponseWithAStrayControlChar() throws Exception {
        // Given
        HttpMessage msg = createMessage("x ".repeat(500_000) + "\u0001<p>" + AWS_KEY + "</p>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldScanMultipartRequestWithAStrayControlChar() throws Exception {
        // Given
        HttpMessage msg =
                createRequest(
                        "POST",
                        "http://example.com/",
                        "multipart/form-data; boundary=x",
                        "x ".repeat(5000) + "\u0001--x\r\n\r\n" + AWS_KEY + "\r\n--x--");
        // When
        scanHttpRequestSend(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    static Stream<Arguments> requestsWithSecret() {
        return Stream.of(
                Arguments.of("GET", "http://example.com/?a=1&k=" + AWS_KEY, "text/plain", ""),
                Arguments.of(
                        "POST",
                        "http://example.com/",
                        "application/x-www-form-urlencoded",
                        "a=1&k=" + AWS_KEY),
                Arguments.of(
                        "POST",
                        "http://example.com/",
                        "application/json",
                        "{\"k\": \"" + AWS_KEY + "\"}"),
                Arguments.of(
                        "PUT", "http://example.com/", "application/xml", "<k>" + AWS_KEY + "</k>"),
                Arguments.of(
                        "PATCH",
                        "http://example.com/",
                        "multipart/form-data; boundary=x",
                        "--x\r\nContent-Disposition: form-data; name=\"k\"\r\n\r\n"
                                + AWS_KEY
                                + "\r\n--x--"));
    }

    @ParameterizedTest
    @MethodSource("requestsWithSecret")
    void shouldRaiseAlertWhenSecretInRequest(
            String method, String url, String contentType, String body) throws Exception {
        // Given
        HttpMessage msg = createRequest(method, url, contentType, body);
        // When
        scanHttpRequestSend(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), containsString(AWS_KEY));
        assertThat(alertsRaised.get(0).getOtherInfo(), containsString("request"));
    }

    @Test
    void shouldNotRaiseAlertWhenRequestIsClean() throws Exception {
        // Given
        HttpMessage msg =
                createRequest("POST", "http://example.com/?a=1", "application/json", "{\"a\": 1}");
        // When
        scanHttpRequestSend(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotScanRequestHeaders() throws Exception {
        // Given
        HttpMessage msg = createRequest("GET", "http://example.com/", "text/plain", "");
        msg.getRequestHeader().setHeader("Authorization", "Bearer " + AWS_KEY);
        // When
        scanHttpRequestSend(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    private static HttpMessage createRequest(
            String method, String url, String contentType, String body) throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(new HttpRequestHeader(method + " " + url + " HTTP/1.1"));
        msg.getRequestHeader().setHeader("Content-Type", contentType);
        msg.setRequestBody(body == null ? "" : body);
        return msg;
    }

    private static HttpMessage createMessage(String body) throws URIException {
        return createMessage("http://example.com", body);
    }

    private static HttpMessage createMessage(String url, String body) throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI(url, false));
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.OK);
        msg.setResponseBody(body);
        return msg;
    }
}
