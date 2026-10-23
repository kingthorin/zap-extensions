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
package org.zaproxy.zap.extension.ascanrules.sqli.strategies;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringEscapeUtils;
import org.parosproxy.paros.core.scanner.AbstractPlugin;

/** Utilities for comparing response bodies in SQL injection detection strategies. */
public final class ResponseBodyUtils {

    private ResponseBodyUtils() {}

    /**
     * Bounded cache of volatile-normalised bodies: normalisation is a pure function of the input.
     */
    private static final int VOLATILE_CACHE_SIZE = 64;

    private static final Map<String, String> VOLATILE_CACHE =
            Collections.synchronizedMap(
                    new LinkedHashMap<String, String>(16, 0.75f, true) {
                        @Override
                        protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
                            return size() > VOLATILE_CACHE_SIZE;
                        }
                    });

    private static final Pattern INPUT_TAG_PATTERN =
            Pattern.compile("<input\\b[^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern VALUE_PATTERN =
            Pattern.compile("(?i)(value\\s*=\\s*[\"'])([^\"'\\s<>]{16,})([\"'])");
    private static final Pattern NAME_PATTERN =
            Pattern.compile("(?i)name\\s*=\\s*[\"']?([^\"'\\s>]+)[\"']?");
    private static final Pattern ISO_TIMESTAMP_PATTERN =
            Pattern.compile(
                    "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}(:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:?\\d{2})?)?");

    /**
     * Removes all occurrences of {@code needle} from {@code text}, case-insensitive.
     *
     * @param text the text to strip from
     * @param needle the substring to remove
     * @return text with needle removed, or empty string if text is null
     */
    static String strip(String text, String needle) {
        if (text == null || text.isEmpty() || needle == null || needle.isEmpty()) {
            return text == null ? "" : text;
        }
        return text.replaceAll("(?i)" + Pattern.quote(needle), "");
    }

    /**
     * Removes all occurrences of the given patterns from {@code text}, stripping multiple encoding
     * forms: literal, URL-encoded, HTML-entity-encoded (single and double), and XML-escaped.
     *
     * <p>This mirrors baseline rule 40018's {@code stripOff} / {@code
     * stripOffOriginalAndAttackParam} logic, which strips the injected value in all its possible
     * encoded forms to avoid the payload itself skewing response-body comparisons.
     *
     * @param text the response body to strip from
     * @param patterns the substrings to remove (e.g., original param value, attack payload)
     * @return text with all patterns and their encoded forms removed
     */
    @SuppressWarnings("deprecation")
    public static String stripAllEncodedForms(String text, String... patterns) {
        if (text == null || text.isEmpty()) {
            return text == null ? "" : text;
        }

        String result = text;
        // Strip longest patterns first: when one pattern is a prefix/substring of another (e.g.
        // "payload" vs the sent value "payload%"), stripping the short one first mangles the long
        // one's occurrence and leaves a partial remnant behind, manufacturing a difference between
        // otherwise identical responses.
        String[] ordered =
                Arrays.stream(patterns)
                        .filter(p -> p != null && !p.isEmpty())
                        .sorted(Comparator.comparingInt(String::length).reversed())
                        .toArray(String[]::new);

        for (String pattern : ordered) {
            // Strip the literal pattern
            result = result.replaceAll("\\Q" + pattern + "\\E", "");

            // Strip URL-encoded form (UTF-8)
            String urlEncoded = URLEncoder.encode(pattern, StandardCharsets.UTF_8);
            result = result.replaceAll("\\Q" + urlEncoded + "\\E", "");

            // Strip HTML-entity-encoded form, using the same numeric entities (&#60;/&#62;) the
            // generic rule (40018) reflects and strips via AbstractPlugin.getHTMLEncode
            String htmlEncoded = AbstractPlugin.getHTMLEncode(pattern);
            result = result.replaceAll("\\Q" + htmlEncoded + "\\E", "");

            // Strip HTML-entity-encoded form of the URL-encoded pattern (double encoding)
            String doubleEncoded = AbstractPlugin.getHTMLEncode(urlEncoded);
            result = result.replaceAll("\\Q" + doubleEncoded + "\\E", "");

            // Strip XML-escaped form (preferred over XML 11 per baseline comment)
            String xmlEscaped = StringEscapeUtils.escapeXml10(pattern);
            result = result.replaceAll("\\Q" + xmlEscaped + "\\E", "");
        }

        return result;
    }

    /** Placeholder that volatile regions are normalised to before comparison. */
    private static final String VOLATILE_PLACEHOLDER = "__VOLATILE__";

    /**
     * Normalises per-request volatile regions (CSRF hidden fields, ISO-8601 timestamps) to a fixed
     * placeholder so rotating tokens do not break response differentials.
     *
     * <p>Results are memoised: normalisation is a pure function of the input body, so repeated
     * calls on the same body (exact path followed by template derivation/matching) reuse the cached
     * value instead of re-running the regex passes.
     *
     * @param text the response body to normalise
     * @return the body with matched volatile regions replaced, or empty string if null
     */
    public static String stripVolatileTokens(String text) {
        if (text == null || text.isEmpty()) {
            return text == null ? "" : text;
        }

        String cached = VOLATILE_CACHE.get(text);
        if (cached != null) {
            return cached;
        }

        String result = text;
        // Hidden-input CSRF tokens: normalise the value of any <input> whose name suggests a
        // CSRF/token role, regardless of attribute order, so rotating tokens do not break diffs.
        Matcher inputMatcher = INPUT_TAG_PATTERN.matcher(result);
        StringBuilder sb = new StringBuilder();
        while (inputMatcher.find()) {
            String tag = inputMatcher.group();
            String replacement = tag;
            if (isCsrfTokenInput(tag)) {
                replacement =
                        VALUE_PATTERN.matcher(tag).replaceAll("$1" + VOLATILE_PLACEHOLDER + "$3");
            }
            inputMatcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        inputMatcher.appendTail(sb);
        result = sb.toString();

        // ISO-8601 timestamps: 2026-01-02T15:04:05 with optional fraction/zone.
        result = ISO_TIMESTAMP_PATTERN.matcher(result).replaceAll(VOLATILE_PLACEHOLDER);

        VOLATILE_CACHE.put(text, result);
        return result;
    }

    private static boolean isCsrfTokenInput(String tag) {
        Matcher nameMatcher = NAME_PATTERN.matcher(tag);
        if (nameMatcher.find()) {
            String name = nameMatcher.group(1).toLowerCase();
            return name.contains("csrf") || name.contains("token");
        }
        return false;
    }
}
