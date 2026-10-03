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

import static org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionScenario.Outcome.FP_PRONE;
import static org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionScenario.Outcome.INJECTABLE;
import static org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionScenario.Outcome.SAFE;
import static org.zaproxy.zap.testutils.RequestCondition.param;

import java.util.List;
import java.util.Set;
import org.zaproxy.zap.testutils.UrlParamValueHandler;

/**
 * The seed corpus of {@link SqlInjectionScenario}s: one row per app shape rule 424242 is judged on.
 *
 * <p>Every fixture reuses a response oracle the rule already needs, so a new row is a handful of
 * lines. A row earns its place by either naming a reported false positive (so the regression is
 * re-testable) or contributing measurable coverage, not by exercising a code path.
 *
 * <p>The CVE-shaped rows (multipart POST, date parameters, ORDER BY position, path parameters,
 * authenticated requests) are deliberately absent: each needs a source CVE, and until they exist
 * the rule cannot show whether it covers those shapes at all.
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
                intCastPageIds());
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
