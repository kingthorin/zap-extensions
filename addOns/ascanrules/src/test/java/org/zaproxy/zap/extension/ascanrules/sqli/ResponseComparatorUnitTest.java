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
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

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

    // -- Volatile templates: learn what moves between two renders, compare the rest exactly. --

    /**
     * The case the template exists for: a counter makes every render differ, so the exact
     * comparison can never match, while the true/false content difference is still there to be seen
     * in the parts that do not move.
     */
    @Test
    void shouldLearnTemplateThatAbsorbsAVolatileCounter() throws Exception {
        // Given
        HttpMessage baseline = response("200 OK", "", "Widget, size 1");
        HttpMessage replay = response("200 OK", "", "Widget, size 2");
        ResponseComparator.VolatileTemplate template = derive(baseline, replay);

        // Then
        assertThat(template, is(notNullValue()));
        assertThat(matches(template, baseline, response("200 OK", "", "Widget, size 3")), is(true));
        assertThat(
                matches(template, baseline, response("200 OK", "", "Widget, size 42")), is(true));
        assertThat(
                matches(template, baseline, response("200 OK", "", "No matching row")), is(false));
    }

    /**
     * Two samples can agree inside a volatile token by coincidence (the leading zero of two
     * counters). The span is snapped to the token boundary, so that coincidence is never baked in
     * as if it were stable content.
     */
    @Test
    void shouldSnapVolatileSpanToTheTokenBoundary() throws Exception {
        // Given
        HttpMessage baseline = response("200 OK", "", "Widget, size 007");
        HttpMessage replay = response("200 OK", "", "Widget, size 011");
        ResponseComparator.VolatileTemplate template = derive(baseline, replay);

        // Then
        assertThat(template, is(notNullValue()));
        assertThat(
                matches(template, baseline, response("200 OK", "", "Widget, size 242")), is(true));
    }

    /**
     * A volatile line between two stable ones: the stable lines stay literal (both anchors), so a
     * probe that changes one of them still fails the template — the wildcard covers the moving
     * line, not the whole page.
     */
    @Test
    void shouldKeepStableLinesAroundAVolatileLine() throws Exception {
        // Given
        HttpMessage baseline = response("200 OK", "", "Title\nsize 1\nFooter");
        HttpMessage replay = response("200 OK", "", "Title\nsize 2\nFooter");
        ResponseComparator.VolatileTemplate template = derive(baseline, replay);

        // Then
        assertThat(template, is(notNullValue()));
        assertThat(
                matches(template, baseline, response("200 OK", "", "Title\nsize 9\nFooter")),
                is(true));
        assertThat(
                matches(template, baseline, response("200 OK", "", "Title\nsize 1\nOther tail")),
                is(false));
        assertThat(
                matches(template, baseline, response("200 OK", "", "Different\nsize 1\nFooter")),
                is(false));
    }

    /** Lines added or removed between renders cannot be aligned safely: give up, exact path. */
    @Test
    void shouldGiveUpWhenLinesAreAddedBetweenRenders() throws Exception {
        // Given
        HttpMessage baseline = response("200 OK", "", "Title\nFooter");
        HttpMessage replay = response("200 OK", "", "Title\nAd\nFooter");

        // Then
        assertThat(derive(baseline, replay), is(nullValue()));
    }

    /** Bodies already equal after stripping mean the exact failure came from elsewhere. */
    @Test
    void shouldGiveUpWhenTheBodiesAreAlreadyEqual() throws Exception {
        // Given
        HttpMessage baseline = response("200 OK", "", "Widget, size 1");
        HttpMessage replay = response("200 OK", "", "Widget, size 1");

        // Then
        assertThat(derive(baseline, replay), is(nullValue()));
    }

    /** Nothing in common at all: a template would be pure wildcard and prove nothing. */
    @Test
    void shouldGiveUpWhenNothingIsStable() throws Exception {
        // Given
        HttpMessage baseline = response("200 OK", "", "aaaa");
        HttpMessage replay = response("200 OK", "", "bbbb");

        // Then
        assertThat(derive(baseline, replay), is(nullValue()));
    }

    /**
     * Bodies past the size cap take the exact path rather than an unbounded derivation — and the
     * give-up has to come from the cap itself, not from a later degenerate case: these two bodies
     * share an 8&nbsp;MiB stable prefix, so without the cap a template would be derived.
     */
    @Test
    void shouldGiveUpWhenTheBodyExceedsTheTemplateCap() throws Exception {
        // Given
        String shared = "x".repeat(8 * 1024 * 1024);
        HttpMessage baseline = response("200 OK", "", shared + "1");
        HttpMessage replay = response("200 OK", "", shared + "2");

        // Then
        assertThat(derive(baseline, replay), is(nullValue()));
    }

    /** A status change is a different outcome, template or not — same rule as the exact compare. */
    @Test
    void shouldNotMatchTemplateWhenStatusDiffers() throws Exception {
        // Given
        HttpMessage baseline = response("200 OK", "", "Widget, size 1");
        HttpMessage replay = response("200 OK", "", "Widget, size 2");
        ResponseComparator.VolatileTemplate template = derive(baseline, replay);

        // Then
        assertThat(template, is(notNullValue()));
        assertThat(
                matches(template, baseline, response("404 Not Found", "", "Widget, size 3")),
                is(false));
    }

    private ResponseComparator.VolatileTemplate derive(HttpMessage baseline, HttpMessage replay) {
        return comparator.deriveVolatileTemplate(
                baseline, ORIGINAL, ORIGINAL, replay, ORIGINAL, ORIGINAL);
    }

    private boolean matches(
            ResponseComparator.VolatileTemplate template, HttpMessage baseline, HttpMessage probe) {
        return comparator.matchesTemplate(
                template, baseline, ORIGINAL, ORIGINAL, probe, ORIGINAL, ORIGINAL);
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
