/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.BDDMockito.given;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;

public class FullPathDiscosureAlertTest
        extends PassiveScannerTest<FullPathDisclosureScanRuleUnitTest> {

    @Test
    void shouldNotRaiseAnyAlertsWhenResponseIsSuccess() throws URIException {
        // Given
        HttpMessage msg = createMessage("", HttpStatusCode.OK);
        given(passiveScanData.isSuccess(msg)).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotRaiseAlertsWhenHTMLTagsLooksLikeUnixPath() throws URIException {
        // Given
        String testBody =
                "\n"
                        + "<!DOCTYPE html>\n"
                        + "<html lang=\"en\">\n"
                        + "<head>\n"
                        + "<meta charset=\"utf-8\">\n"
                        + "<title>Error</title>\n"
                        + "</head>\n"
                        + "<body>\n"
                        + "<pre>Cannot GET /</pre>\n"
                        + "</body>\n"
                        + "</html>\n";
        HttpMessage message = createMessage(testBody, HttpStatusCode.NOT_FOUND);
        given(passiveScanData.isSuccess(message)).willReturn(false);
        // When
        scanHttpResponseReceive(message);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldRaiseLowRiskAlertWhenWindowsFullPathIsDisclosed() throws URIException {
        // Given
        String testBody =
                "<pre>Error: Failed to lookup view &quot;no&quot; in views directory &quot;D:\\Software\\testingServer/public&quot;<br> &nbsp; &nbsp;at Function.render (D:\\Software\\testingServer\\node_modules\\express\\lib\\application.js:597:17)<br> &nbsp; &nbsp;at ServerResponse.render (D:\\Software\\testingServer\\node_modules\\express\\lib\\response.js:1039:7)<br> &nbsp; &nbsp;at D:\\Software\\testingServer\\index.js:14:9<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (D:\\Software\\testingServer\\node_modules\\express\\lib\\router\\layer.js:95:5)<br> &nbsp; &nbsp;at next (D:\\Software\\testingServer\\node_modules\\express\\lib\\router\\route.js:144:13)<br> &nbsp; &nbsp;at Route.dispatch (D:\\Software\\testingServer\\node_modules\\express\\lib\\router\\route.js:114:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (D:\\Software\\testingServer\\node_modules\\express\\lib\\router\\layer.js:95:5)<br> &nbsp; &nbsp;at D:\\Software\\testingServer\\node_modules\\express\\lib\\router\\index.js:284:15<br> &nbsp; &nbsp;at Function.process_params (D:\\Software\\testingServer\\node_modules\\express\\lib\\router\\index.js:346:12)<br> &nbsp; &nbsp;at next (D:\\Software\\testingServer\\node_modules\\express\\lib\\router\\index.js:280:10)</pre>\n"
                        + "</body>\n"
                        + "</html>\n";
        HttpMessage msg = createMessage(testBody, HttpStatusCode.NOT_FOUND);
        given(passiveScanData.isSuccess(msg)).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals(alertsRaised.get(0).getRisk(), Alert.RISK_LOW);
    }

    @Test
    void shouldRaiseLowRiskAlertWhenUnixBasedFullPathIsDisclosed() throws URIException {
        // Given
        String testBody =
                "<pre>Error: Failed to lookup view &quot;no&quot; in views directory &quot;/home/Software/testingServer/public&quot;<br> &nbsp; &nbsp;at Function.render (/home/Software/testingServer/node_modules/express/lib/application.js:597:17)<br> &nbsp; &nbsp;at ServerResponse.render (D:\\Software\\testingServer\\node_modules\\express\\lib\\response.js:1039:7)<br> &nbsp; &nbsp;at D:\\Software\\testingServer\\index.js:14:9<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (D:\\Software\\testingServer\\node_modules\\express\\lib\\router\\layer.js:95:5)<br> &nbsp; &nbsp;at next (D:\\Software\\testingServer\\node_modules\\express\\lib\\router\\route.js:144:13)<br> &nbsp; &nbsp;at Route.dispatch (D:\\Software\\testingServer\\node_modules\\express\\lib\\router\\route.js:114:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (D:\\Software\\testingServer\\node_modules\\express\\lib\\router\\layer.js:95:5)<br> &nbsp; &nbsp;at D:\\Software\\testingServer\\node_modules\\express\\lib\\router\\index.js:284:15<br> &nbsp; &nbsp;at Function.process_params (D:\\Software\\testingServer\\node_modules\\express\\lib\\router\\index.js:346:12)<br> &nbsp; &nbsp;at next (D:\\Software\\testingServer\\node_modules\\express\\lib\\router\\index.js:280:10)</pre>\n"
                        + "</body>\n"
                        + "</html>\n";
        HttpMessage msg = createMessage(testBody, HttpStatusCode.NOT_FOUND);
        given(passiveScanData.isSuccess(msg)).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals(alertsRaised.get(0).getRisk(), Alert.RISK_LOW);
    }

    @Test
    void shouldRaiseAlertOfLowConfidence() throws URIException {
        // Given
        HttpMessage msg =
                createMessage("Error : Cant find /sample/path/", HttpStatusCode.NOT_FOUND);
        given(passiveScanData.isSuccess(msg)).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals(alertsRaised.get(0).getConfidence(), Alert.CONFIDENCE_LOW);
    }

    @Test
    void shouldNotRaiseAlertsWithHATEOSResponseWhenResponseIsSuccess() throws URIException {
        // Given
        HttpMessage msg =
                createMessage(
                        "{ \"payroll\": { \"employee_number\": \"employee_123\", \"salary\" : 1000, \"links\": { \"increment\": \"/payroll/employee_123/increment\", \"decrement\": \"/payroll/employee_123/decrement\", \"close\": \"/payroll/employee_123/close\" } } }\n"
                                + "Here \"/payroll/employee_123/increment\"",
                        HttpStatusCode.OK);
        given(passiveScanData.isSuccess(msg)).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotRaiseAlertsForLinksWhenResponseIsSuccess() throws URIException {
        // Given
        HttpMessage msg =
                createMessage("<a href=\"https://example.com/foo/bar/\">", HttpStatusCode.OK);
        given(passiveScanData.isSuccess(msg)).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldContainAllMatchedPathsInEvidence() throws URIException {
        // Given
        String body =
                "/usr/somePath/ unmatched text in between /home/foo/bar some more text followed by windows Style path C:\\Users\\username\\server\\";
        HttpMessage msg = createMessage(body, HttpStatusCode.INTERNAL_SERVER_ERROR);
        given(passiveScanData.isSuccess(msg)).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        String evidence = alertsRaised.get(0).getEvidence();
        assertTrue(evidence.contains("/usr"));
        assertTrue(evidence.contains("/usr/somePath/"));
        assertTrue(evidence.contains("/home"));
        assertTrue(evidence.contains("/home/foo/"));
        assertTrue(evidence.contains("\\Users"));
        assertTrue(evidence.contains("C:\\Users\\username\\server\\"));
    }

    @Override
    protected FullPathDisclosureScanRuleUnitTest createScanner() {
        return new FullPathDisclosureScanRuleUnitTest();
    }

    private HttpMessage createMessage(String body, Integer status) throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.getResponseHeader().setStatusCode(status);
        msg.setResponseBody(body);
        return msg;
    }
}
