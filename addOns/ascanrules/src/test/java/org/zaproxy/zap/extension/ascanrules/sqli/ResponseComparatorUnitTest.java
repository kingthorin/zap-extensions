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

/** Pure-logic unit test for {@link ResponseComparator} -- no HTTP server needed. */
class ResponseComparatorUnitTest {

    private static final String ORIGINAL = "jsmith";
    private static final String CONTROL = "jsmithS4feV4lu3";

    private final ResponseComparator comparator = new ResponseComparator();

    /**
     * The case the strict compare exists for: two 301s whose {@code Location} echoes a different
     * value are the same landing page, so the parameter has no effect on the outcome.
     */
    @Test
    void shouldMatchRedirectsThatOnlyDifferInTheEchoedLocation() throws Exception {
        // Given
        HttpMessage baseline = response("301 Moved", "Location: /landing?q=" + ORIGINAL, "");
        HttpMessage control = response("301 Moved", "Location: /landing?q=" + CONTROL, "");
        // Then
        assertThat(
                comparator.isIndistinguishableFromBenignControl(
                        baseline, ORIGINAL, control, CONTROL),
                is(true));
    }

    /**
     * Strict, not fuzzy: a page that answers differently is not "indistinguishable", however near.
     */
    @Test
    void shouldNotMatchSamePageWithADifferentAnswer() throws Exception {
        // Given
        HttpMessage baseline = response("200 OK", "", "<html><body>1 booking found</body></html>");
        HttpMessage control = response("200 OK", "", "<html><body>2 bookings found</body></html>");
        // Then
        assertThat(
                comparator.isIndistinguishableFromBenignControl(
                        baseline, ORIGINAL, control, CONTROL),
                is(false));
        assertThat(comparator.isSimilar(baseline, ORIGINAL, control, CONTROL), is(true));
    }

    /** Different status is a different outcome, whatever the body says. */
    @Test
    void shouldNotMatchDifferentStatus() throws Exception {
        // Given
        HttpMessage baseline = response("200 OK", "", "<html><body>ok</body></html>");
        HttpMessage control = response("404 Not Found", "", "<html><body>ok</body></html>");
        // Then
        assertThat(
                comparator.isIndistinguishableFromBenignControl(
                        baseline, ORIGINAL, control, CONTROL),
                is(false));
    }

    private static HttpMessage response(String statusLine, String extraHeader, String body)
            throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET /search?q=x HTTP/1.1\r\nHost: example\r\n\r\n");
        msg.setResponseHeader(
                "HTTP/1.1 "
                        + statusLine
                        + "\r\nContent-Type: text/html\r\n"
                        + extraHeader
                        + "\r\n");
        msg.setResponseBody(body);
        return msg;
    }
}
