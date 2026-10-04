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

import static org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionScenario.Outcome.BLIND;
import static org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionScenario.Outcome.FP_PRONE;
import static org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionScenario.Outcome.INJECTABLE;
import static org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionScenario.Outcome.SAFE;
import static org.zaproxy.zap.testutils.RequestCondition.formParam;
import static org.zaproxy.zap.testutils.RequestCondition.param;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.zaproxy.zap.testutils.UrlParamValueHandler;

/**
 * The seed corpus of {@link SqlInjectionScenario}s: one row per app shape rule 424242 is judged on.
 *
 * <p>Every fixture reuses a response oracle the rule already needs, so a new row is a handful of
 * lines. A row earns its place by either naming a reported false positive (so the regression is
 * re-testable) or contributing measurable coverage, not by exercising a code path.
 *
 * <p>The CVE-shaped rows carry their source and the shape it came from. Two shapes that real,
 * recently exploited SQL injection turns up in have no row, because a row has to be runnable and
 * neither is reachable from here:
 *
 * <ul>
 *   <li>**Injection through an HTTP header.** MOVEit Transfer (CVE-2023-34362, exploited in the
 *       wild) injects through {@code X-siLock-SessVar2}, not a parameter. This rule is an {@code
 *       AbstractAppParamPlugin}, so it scans parameters only: the shape is out of reach by
 *       construction, not by accident.
 *   <li>**Multipart form bodies.** The harness parses urlencoded bodies, so the Royal Event row
 *       (CVE-2022-28080) keeps the parameter and value shape but not the multipart transport.
 * </ul>
 *
 * <p>Both are recorded here rather than left implicit, because a coverage limit that is written
 * down is a decision and one that is not is a surprise.
 */
public final class SqlInjectionScenarioCorpus {

    private SqlInjectionScenarioCorpus() {}

    /** The body a page returns for an ordinary request. */
    public static final String NORMAL_CONTENT = "Some Content, matching row found";

    /** Page ids that exist, for the int-cast scenarios. */
    public static final Set<String> EXISTING_IDS = Set.of("1", "2", "3");

    /** The corpus, in reporting order. */
    public static List<SqlInjectionScenario> scenarios() {
        return List.of(
                errorTextInServerError(),
                booleanInjected(),
                echoOnlySearch(),
                rateLimitedFalseCondition(),
                wafForbiddenOnPayload(),
                intCastPageIds(),
                wordpressTaxQuery(),
                wordPressSearchOrderBy(),
                blindDateFilter());
    }

    /** The body a POST scenario sends before the parameter under test, kept short on purpose. */
    private static final String FORM_PREFIX = "action=search&";

    /**
     * WordPress core before 5.8.3 built the SQL for {@code WP_Query} from an unsanitised {@code
     * tax_query} value in an AJAX form field, so the injection sits inside a JSON document carried
     * by a form parameter rather than in the parameter value itself (CVE-2022-21661, ZDI-22-020).
     */
    private static SqlInjectionScenario wordpressTaxQuery() {
        return new SqlInjectionScenario(
                "wordpress-tax-query-json",
                INJECTABLE,
                "CVE-2022-21661, ZDI-22-020",
                "/wp-admin/admin-ajax.php",
                FORM_PREFIX
                        + "query_vars=%7B%22tax_query%22%3A%7B%220%22%3A%7B%22terms%22%3A%5B%22shoes%22%5D%7D%7D%7D",
                () ->
                        UrlParamValueHandler.builder()
                                .targetPath("/wp-admin/admin-ajax.php")
                                .targetParam("query_vars")
                                .when(
                                        formParam("query_vars")
                                                .matches(
                                                        value ->
                                                                value.contains("'")
                                                                        || value.contains("UNION")))
                                .thenReturn(
                                        200,
                                        "You have an error in your SQL syntax near '' at line 1")
                                .fallbackHtmlResponse("<li>No products found</li>")
                                .build());
    }

    /**
     * An {@code ORDER BY} position parameter: the WordPress bulk editor passed {@code orderby}
     * through {@code esc_sql()} straight into the query, which escapes quotes but not a subquery
     * appended after a comma (WordPress SEO by Yoast &le; 1.7.3.3, Exploit-DB 36413, WPVULNDB
     * 7841).
     *
     * <p>Labelled {@link SqlInjectionScenario.Outcome#BLIND} because that is what the published
     * proof of concept observes — the query executes and the page sleeps — while the response is
     * the same either way. A rule with a time-based technique would catch it; this one has none, so
     * the row documents a known limit rather than pretending the shape is undetectable in
     * principle.
     */
    private static SqlInjectionScenario wordPressSearchOrderBy() {
        return new SqlInjectionScenario(
                "wordpress-bulk-editor-orderby",
                BLIND,
                "Exploit-DB 36413, WPVULNDB 7841",
                "/wp-admin/admin.php?page=wpseo_bulk-editor&type=title&order=asc",
                "",
                () ->
                        UrlParamValueHandler.builder()
                                .targetPath("/wp-admin/admin.php")
                                .targetParam("orderby")
                                .fallbackHtmlResponse("<table id=\"bulk-editor\"></table>")
                                .build());
    }

    /**
     * A date-range filter parameter behind a login, injectable through a {@code UNION} that
     * reflects a random canary back in the response — the shape of the published proof of concept
     * for the Royal Event management system (CVE-2022-28080, Exploit-DB 50934). It is the corpus's
     * only canary-reflection row so far, and the reason canary reflection is on the roadmap.
     *
     * <p>The published proof of concept posts the filter as {@code multipart/form-data}; the test
     * harness parses urlencoded bodies, so the fixture uses the same parameter with the same value
     * shape over a urlencoded POST. The multipart transport itself is therefore untested.
     */
    private static SqlInjectionScenario blindDateFilter() {
        return new SqlInjectionScenario(
                "royal-event-date-filter-canary",
                INJECTABLE,
                "CVE-2022-28080, Exploit-DB 50934",
                "/royal_event/btndates_report.php",
                FORM_PREFIX + "todate=01%2F01%2F2011&search=3&fromdate=01%2F01%2F2011",
                () ->
                        UrlParamValueHandler.builder()
                                .targetPath("/royal_event/btndates_report.php")
                                .targetParam("todate")
                                .when(
                                        formParam("todate")
                                                .matches(
                                                        SqlInjectionScenarioCorpus
                                                                ::unionHas15Columns))
                                .thenReturn(
                                        200,
                                        "<td class=\"data\">e10adc3949ba59abbe56e057f20f883e</td>")
                                .when(
                                        formParam("todate")
                                                .matches(
                                                        value ->
                                                                value.toUpperCase(Locale.ROOT)
                                                                        .contains("UNION")))
                                .thenReturn(
                                        200,
                                        "The used SELECT statements have a different number of"
                                                + " columns")
                                .fallbackHtmlResponse("<td class=\"data\">No bookings</td>")
                                .build());
    }

    /**
     * Whether the value is a {@code UNION} selecting the 15 columns the published proof of concept
     * needs: thirteen {@code NULL}s, a canary, and a trailing {@code NULL}. A {@code UNION} with
     * any other number of columns is what a real application rejects with a database error, which
     * is the signal the rule is expected to find here; the canary reflection is Step 6's business.
     */
    private static boolean unionHas15Columns(String value) {
        if (value == null || !value.toUpperCase(Locale.ROOT).contains("UNION")) {
            return false;
        }
        int columns = 0;
        for (String column : value.split("(?i)union\\s+(all\\s+)?select", 2)[1].split(",")) {
            if (!column.isBlank()) {
                columns++;
            }
        }
        return columns == 15;
    }

    /**
     * A page printing a database error verbatim in a {@code 500} response once the parameter
     * carries a quote. Nothing about this is a false positive to be filtered, it is the clearest
     * evidence there is (reported as zaproxy/zaproxy#557).
     */
    private static SqlInjectionScenario errorTextInServerError() {
        return new SqlInjectionScenario(
                "sqlite-error-in-500",
                INJECTABLE,
                "zaproxy/zaproxy#557",
                "/rest/products/search?q=shoes",
                "",
                () ->
                        UrlParamValueHandler.builder()
                                .targetPath("/rest/products/search")
                                .targetParam("q")
                                .fallbackHtmlResponse(NORMAL_CONTENT)
                                .errorOracle(500, "near \"'\": syntax error")
                                .build());
    }

    /**
     * A numeric parameter whose AND_TRUE condition reproduces the baseline and AND_FALSE does not.
     */
    private static SqlInjectionScenario booleanInjected() {
        return new SqlInjectionScenario(
                "boolean-injected-id",
                INJECTABLE,
                "WAVSEP-style",
                "/item?id=1",
                "",
                () ->
                        UrlParamValueHandler.builder()
                                .targetPath("/item")
                                .targetParam("id")
                                .when(
                                        param("id")
                                                .matches(
                                                        SqlInjectionScenarioCorpus
                                                                ::isFalseCondition))
                                .thenReturn("No matching row")
                                .fallbackHtmlResponse(NORMAL_CONTENT)
                                .build());
    }

    /**
     * A search page echoing whatever it is given and never changing its result set: the safe
     * counterpart of the rows below, and the row that catches a guard filtering too much.
     */
    private static SqlInjectionScenario echoOnlySearch() {
        return new SqlInjectionScenario(
                "echo-only-search",
                SAFE,
                "WAVSEP-style",
                "/search?q=shoes",
                "",
                () ->
                        UrlParamValueHandler.builder()
                                .targetPath("/search")
                                .targetParam("q")
                                .reflectedPayload("No results for: ", "")
                                .build());
    }

    /**
     * The false condition of a boolean pair answered with {@code 429 Too Many Requests} while the
     * original value and the true condition are answered normally (zaproxy/zaproxy#8652).
     */
    private static SqlInjectionScenario rateLimitedFalseCondition() {
        return new SqlInjectionScenario(
                "rate-limited-false-condition",
                FP_PRONE,
                "zaproxy/zaproxy#8652",
                "/item?id=1",
                "",
                () -> errorPageOnFalseCondition(429, "too many requests"));
    }

    /**
     * A static asset served with a cache-buster parameter, where a WAF rejects payloads that look
     * like SQL with {@code 403 Forbidden} and the asset itself is served with {@code 200} (the
     * shape reported as zaproxy/zaproxy#8653, and behind the flood in zaproxy/zaproxy#8636).
     */
    private static SqlInjectionScenario wafForbiddenOnPayload() {
        return new SqlInjectionScenario(
                "static-asset-waf-forbidden",
                FP_PRONE,
                "zaproxy/zaproxy#8653, zaproxy/zaproxy#8636",
                "/static/app.min.js?v=8f2a1c",
                "",
                () ->
                        UrlParamValueHandler.builder()
                                .targetPath("/static/app.min.js")
                                .targetParam("v")
                                .when(
                                        param("v")
                                                .matches(
                                                        SqlInjectionScenarioCorpus
                                                                ::looksLikePayload))
                                .thenReturn(403, "Request blocked by WAF")
                                .fallbackHtmlResponse("var app={};")
                                .build());
    }

    /**
     * A numeric parameter cast to an integer, as WordPress does with {@code ?p=}: every existing id
     * answers with the same page and every non-existing id with {@code 404}, so the confirming
     * expression only ever differs by its error page (zaproxy/zaproxy#8651, zaproxy/zaproxy#9289).
     */
    private static SqlInjectionScenario intCastPageIds() {
        return new SqlInjectionScenario(
                "int-cast-page-ids",
                FP_PRONE,
                "zaproxy/zaproxy#8651, zaproxy/zaproxy#9289",
                "/page?id=1",
                "",
                () ->
                        UrlParamValueHandler.builder()
                                .targetPath("/page")
                                .targetParam("id")
                                .when(
                                        param("id")
                                                .matches(
                                                        value ->
                                                                EXISTING_IDS.contains(
                                                                        leadingDigits(value))))
                                .thenReturn("")
                                .when(param("id").matches(value -> true))
                                .thenReturn(404, "Not found")
                                .build());
    }

    private static UrlParamValueHandler errorPageOnFalseCondition(int statusCode, String body) {
        return UrlParamValueHandler.builder()
                .targetPath("/item")
                .targetParam("id")
                .when(param("id").matches(SqlInjectionScenarioCorpus::isFalseCondition))
                .thenReturn(statusCode, body)
                .fallbackHtmlResponse(NORMAL_CONTENT)
                .build();
    }

    /**
     * Whether the value carries the AND_FALSE half of one of the boolean condition pairs. These
     * markers have to follow {@code BooleanConditionPayloads.CONDITIONS}, so this is the one place
     * in the corpus that knows how those payloads look.
     *
     * @param value the parameter value sent
     * @return true if it is the false half of a pair
     */
    public static boolean isFalseCondition(String value) {
        return value != null
                && (value.contains("2>3")
                        || value.contains("BETWEEN 5 AND 6")
                        || value.contains("LIKE 'z%")
                        || value.contains("IS NOT NULL"));
    }

    /** Whether the value looks like an injection attempt rather than a plain cache-buster value. */
    private static boolean looksLikePayload(String value) {
        return value != null
                && (value.contains("'")
                        || value.contains("\"")
                        || value.contains(" OR ")
                        || value.contains(" AND ")
                        || value.contains("--"));
    }

    /**
     * The leading integer of a value, which is what an application casting the parameter to an
     * integer effectively uses: {@code 3-2} starts from 3 and {@code 2/2} from 2.
     *
     * @param value the parameter value sent
     * @return the leading digits, or an empty string if there are none
     */
    public static String leadingDigits(String value) {
        if (value == null) {
            return "";
        }
        int end = 0;
        while (end < value.length() && Character.isDigit(value.charAt(end))) {
            end++;
        }
        return value.substring(0, end);
    }
}
