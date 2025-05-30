/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class CsrfCountermeasuresScanRuleUnitTest extends PassiveScannerTest<CsrfCountermeasuresScanRule> {

    private ExtensionAntiCSRF extensionAntiCSRFMock;
    private List<String> antiCsrfTokenNames;
    private HttpMessage msg;

    @BeforeEach
    void before() throws URIException {
        antiCsrfTokenNames = new ArrayList<>();
        antiCsrfTokenNames.add("token");
        antiCsrfTokenNames.add("csrfToken");
        antiCsrfTokenNames.add("csrf-token");

        extensionAntiCSRFMock =
                mock(ExtensionAntiCSRF.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionAntiCSRFMock.getAntiCsrfTokenNames()).willReturn(antiCsrfTokenNames);
        given(extensionAntiCSRFMock.isAntiCsrfToken(any()))
                .willAnswer(
                        invocation -> {
                            return antiCsrfTokenNames.contains(
                                    invocation.getArgument(0, String.class));
                        });
        OptionsParam options = Model.getSingleton().getOptionsParam();
        options.load(new ZapXmlConfiguration());
        rule.setExtensionAntiCSRF(extensionAntiCSRFMock);
        rule.setCsrfIgnoreList("");
        rule.setCSRFIgnoreAttName("");
        rule.setCSRFIgnoreAttValue("");
        rule.setAlertThreshold(AlertThreshold.MEDIUM);

        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        HttpResponseHeader responseHeader = new HttpResponseHeader();
        responseHeader.setStatusCode(200);
        responseHeader.setHeader(HttpHeader.CONTENT_TYPE, "text/html");

        msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.setResponseHeader(responseHeader);
    }

    @Override
    protected CsrfCountermeasuresScanRule createScanner() {
        return new CsrfCountermeasuresScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(6)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_SESS_05_CSRF.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_SESS_05_CSRF.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_SESS_05_CSRF.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlerts() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
    }

    @Test
    void shouldNotRaiseAlertIfContentTypeIsNotHTML() {
        // Given
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, "application/json");
        formWithoutAntiCsrfToken();
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldNotRaiseAlertIfThereIsNoHTML() {
        // Given
        msg.setResponseBody("no html");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldNotRaiseAlertIfThereIsNoForm() {
        // Given
        msg.setResponseBody("<html><head></head><body><p>no form</p></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldNotRaiseAlertIfFormHasNoParent() {
        // Given
        msg.setResponseBody(
                "<form id=\"no_csrf_token\" method=\"POST\"><input type=\"text\"/><input type=\"submit\"/></form>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldRaiseAlertIfThereIsNoCSRFTokenFound() {
        // Given
        formWithoutAntiCsrfToken();
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(9, alertsRaised.get(0).getWascId());
        assertEquals(
                "<form id=\"no_csrf_token\" method=\"POST\">", alertsRaised.get(0).getEvidence());
    }

    @Test
    void shouldRaiseAlertWithSortedFormFieldsInOtherInfoIfThereIsNoCSRFTokenFound() {
        // Given
        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form id=\"no_csrf_token\" method=\"POST\">"
                        + "    <input type=\"text\" id=\"Cat\"/>"
                        + "    <input type=\"text\" id=\"car\"/>"
                        + "    <input type=\"text\" id=\"Bat\"/>"
                        + "    <input type=\"text\" id=\"bar\"/>"
                        + "    <input type=\"text\" id=\"art\"/>"
                        + "    <input type=\"submit\"/>"
                        + "</form></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(
                alertsRaised
                        .get(0)
                        .getOtherInfo()
                        .contains("\"art\" \"bar\" \"Bat\" \"car\" \"Cat\""));
    }

    @Test
    void shouldRaiseAlertWithSortedUniqueFormFieldsInOtherInfoIfThereIsNoCSRFTokenFound() {
        // Given
        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form id=\"no_csrf_token\" method=\"POST\">"
                        + "    <input type=\"text\" id=\"Id\"/>"
                        + "    <input type=\"text\" id=\"username\"/>"
                        + "    <input type=\"text\" id=\"Key\"/>"
                        + "    <input type=\"text\" id=\"group\"/>"
                        + "    <input type=\"text\" id=\"group\"/>"
                        + "    <input type=\"text\" id=\"group\"/>"
                        + "    <input type=\"text\" id=\"group\"/>"
                        + "    <input type=\"text\" id=\"group\"/>"
                        + "    <input type=\"submit\"/>"
                        + "</form></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertTrue(
                alertsRaised
                        .get(0)
                        .getOtherInfo()
                        .contains("\"group\" \"Id\" \"Key\" \"username\""));
    }

    @Test
    void shouldNotRaiseAlertWhenThereIsOnlyOneFormWithFirstKnownCSRFTokenUsingName() {
        // Given
        msg.setResponseBody(
                "<html><head></head><body><form id=\"form_name\"  method=\"POST\"><input type=\"text\" name=\"token\"/><input type=\"submit\"/></form></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldNotRaiseAlertWhenThereIsOnlyOneFormWithAKnownCSRFTokenUsingId() {
        // Given
        msg.setResponseBody(
                "<html><head></head><body><form id=\"form_name\"  method=\"POST\"><input type=\"text\" id=\"token\"/><input type=\"submit\"/></form></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldNotRaiseAlertWhenThereIsOnlyOneFormWithSecondKnownCSRFTokenUsingName() {
        // Given
        msg.setResponseBody(
                "<html><head></head><body><form id=\"form_name\"  method=\"POST\"><input type=\"text\" name=\"csrfToken\"/><input type=\"submit\"/></form></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldRaiseOneAlertForOneFormWhenSecondFormHasAKnownCSRFToken() {
        // Given
        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form id=\"second_form\" method=\"POST\"><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "<form id=\"first_form\" method=\"POST\"><input type=\"text\" name=\"csrfToken\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(
                alertsRaised.get(0).getEvidence(), "<form id=\"second_form\" method=\"POST\">");
    }

    @Test
    void
            shouldRaiseOneAlertForOneFormWhenOtherFormHasAKnownCSRFTokenAndFormsAreSkippedDueToNonPostMethod() {
        // Given
        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form id=\"first_form\"><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "<form id=\"second_form\" method=\"POST\"><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "<form id=\"third_form\" method=\"GET\"><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "<form id=\"fourth_form\" method=\"POST\"><input type=\"text\" name=\"csrfToken\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(
                alertsRaised.get(0).getEvidence(), "<form id=\"second_form\" method=\"POST\">");
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                is(
                        equalTo(
                                "No known Anti-CSRF token [token, csrfToken, csrf-token] was found in the following HTML form: [Form 2: \"name\" ].")));
    }

    @Test
    void shouldRaiseOneAlertForOneFormWhenFirstFormOfTwoHasAKnownCSRFToken() {
        // Given
        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form id=\"first_form\" method=\"POST\"><input type=\"text\" name=\"csrfToken\"/><input type=\"submit\"/></form>"
                        + "<form id=\"second_form\" method=\"POST\"><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(
                alertsRaised.get(0).getEvidence(), "<form id=\"second_form\" method=\"POST\">");
    }

    @Test
    void shouldRaiseTwoAlertsForTwoFormsWhenOneOfThreeHasAKnownCSRFToken() {
        // Given
        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form id=\"zeroth_form\" method=\"POST\" action=\"someaction\"><input type=\"text\" name=\"zero\"/><input type=\"submit\"/></form>"
                        + "<form id=\"first_form\" method=\"POST\"><input type=\"text\" name=\"csrfToken\"/><input type=\"submit\"/></form>"
                        + "<form id=\"second_form\" method=\"POST\"><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(2, alertsRaised.size());
        assertEquals(
                "<form id=\"zeroth_form\" method=\"POST\" action=\"someaction\">",
                alertsRaised.get(0).getEvidence());
        assertEquals(
                "<form id=\"second_form\" method=\"POST\">", alertsRaised.get(1).getEvidence());
    }

    @Test
    void shouldNotRaiseAlertWhenFormIdIsOnCsrfIgnoreList() {
        // Given
        rule.setCsrfIgnoreList("ignoredName,otherName");

        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form id=\"ignoredName\" method=\"POST\"><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldNotRaiseAlertWhenFormNameIsOnCsrfIgnoreList() {
        // Given
        rule.setCsrfIgnoreList("ignoredName,otherName");

        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form name=\"otherName\" method=\"POST\"><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldRaiseInfoAlertWhenFormAttributeIsOnCsrfAttributeIgnoreList() {
        // Given
        rule.setCSRFIgnoreAttName("data-no-csrf");

        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form name=\"someName\" method=\"POST\" data-no-csrf><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(Alert.RISK_INFO, alertsRaised.get(0).getRisk());
    }

    @Test
    void shouldRaiseInfoAlertWhenFormAttributeAndValueMatchRuleConfig() {
        // Given
        rule.setCSRFIgnoreAttName("data-no-csrf");
        rule.setCSRFIgnoreAttValue("data-no-csrf");

        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form name=\"someName\" method=\"POST\" data-no-csrf=\"data-no-csrf\"><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(Alert.RISK_INFO, alertsRaised.get(0).getRisk());
    }

    @Test
    void shouldRaiseMediumAlertWhenFormAttributeAndRuleConfigMismatch() {
        // Given
        rule.setCSRFIgnoreAttName("ignore");

        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form name=\"someName\" method=\"POST\" data-no-csrf><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(Alert.RISK_MEDIUM, alertsRaised.get(0).getRisk());
    }

    @Test
    void shouldNotRaiseAlertWhenThresholdHighAndMessageOutOfScope() throws URIException {
        // Given
        rule.setCSRFIgnoreAttName("ignore");
        HttpMessage msg = createScopedMessage(false);
        // When
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.HIGH);
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldRaiseAlertWhenThresholdHighAndMessageInScope() throws URIException {
        // Given
        rule.setCSRFIgnoreAttName("ignore");
        HttpMessage msg = createScopedMessage(true);
        // When
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.HIGH);
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
    }

    @ParameterizedTest
    @EnumSource(
            value = AlertThreshold.class,
            names = {"MEDIUM", "LOW"})
    void shouldRaiseAlertBelowHighThresholdAndOutOfScope(AlertThreshold threshold)
            throws URIException {
        // Given
        rule.setCSRFIgnoreAttName("ignore");
        HttpMessage msg = createScopedMessage(false);
        // When
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(threshold);
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldRaiseAlertOnGetAtLowThresholdRegardlessOfScope(boolean isInScope)
            throws URIException {
        // Given
        rule.setCSRFIgnoreAttName("ignore");
        HttpMessage msg = createScopedMessage(isInScope, HttpRequestHeader.GET);
        // When
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.LOW);
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
    }

    private static Stream<Arguments> provideNonLowThresholdsAndBooleans() {
        return Stream.of(
                Arguments.of(AlertThreshold.MEDIUM, true),
                Arguments.of(AlertThreshold.MEDIUM, false),
                Arguments.of(AlertThreshold.HIGH, true),
                Arguments.of(AlertThreshold.HIGH, false));
    }

    @ParameterizedTest
    @MethodSource("provideNonLowThresholdsAndBooleans")
    void shouldNotRaiseAlertOnGetAtNonLowThresholdRegardlessOfScope(
            AlertThreshold threshold, boolean isInScope) throws URIException {
        // Given
        rule.setCSRFIgnoreAttName("ignore");
        HttpMessage msg = createScopedMessage(isInScope, HttpRequestHeader.GET);
        // When
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(threshold);
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @ParameterizedTest
    @ArgumentsSource(GetsArgumentsProvider.class)
    void shouldRaiseAlertOnGetAtLowThresholdRegardlessOfMethodCase(String get) throws URIException {
        // Given
        rule.setCSRFIgnoreAttName("ignore");
        msg = createScopedMessage(true, get);
        // When
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.LOW);
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
    }

    @ParameterizedTest
    @ArgumentsSource(GetsArgumentsProvider.class)
    void shouldNotRaiseAlertOnGetAtNonLowThresholdRegardlessOfMethodCase(String get)
            throws URIException {
        // Given
        rule.setCSRFIgnoreAttName("ignore");
        msg = createScopedMessage(true, get);
        // When
        rule.setConfig(new ZapXmlConfiguration());
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @ParameterizedTest
    @ArgumentsSource(PostsArgumentsProvider.class)
    void shouldRaiseAlertOnPostRegardlessOfMethodCase(String post) throws URIException {
        // Given
        rule.setCSRFIgnoreAttName("ignore");
        msg = createScopedMessage(true, post);
        // When
        rule.setConfig(new ZapXmlConfiguration());
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
    }

    void formWithoutAntiCsrfToken() {
        msg.setResponseBody(
                "<html><head></head><body><form id=\"no_csrf_token\" method=\"POST\"><input type=\"text\"/><input type=\"submit\"/></form></body></html>");
    }

    private static HttpMessage createScopedMessage(boolean isInScope) throws URIException {
        return createScopedMessage(isInScope, HttpRequestHeader.POST);
    }

    private static HttpMessage createScopedMessage(boolean isInScope, String method)
            throws URIException {
        HttpMessage newMsg =
                new HttpMessage() {
                    @Override
                    public boolean isInScope() {
                        return isInScope;
                    }
                };
        newMsg.getRequestHeader().setURI(new URI("http://", "localhost", "/", ""));
        newMsg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, "text/html");
        newMsg.setResponseBody(
                "<html><head></head><body>"
                        + "<form name=\"someName\" method=\""
                        + method
                        + "\" data-no-csrf><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        return newMsg;
    }

    static class GetsArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return List.of(Arguments.of("GET"), Arguments.of("get"), Arguments.of("gEt")).stream();
        }
    }

    static class PostsArgumentsProvider implements ArgumentsProvider {
        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return List.of(Arguments.of("POST"), Arguments.of("post"), Arguments.of("pOst"))
                    .stream();
        }
    }
}
