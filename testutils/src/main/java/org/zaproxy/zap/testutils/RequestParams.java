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
package org.zaproxy.zap.testutils;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Method;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.function.Predicate;

/**
 * The request parameters of a {@link IHTTPSession}, separated by the place they were sent in.
 *
 * <p>NanoHTTPD only decodes the query string parameters, body parameters have to be consumed and
 * decoded by the handler. This class does both, so conditions can be written against query (GET)
 * parameters, form (POST) parameters, or either of them.
 */
class RequestParams {

    private static final String CONTENT_TYPE = "content-type";
    private static final String FORM_URL_ENCODED = "application/x-www-form-urlencoded";

    private final Map<String, List<String>> queryParams;
    private final Map<String, List<String>> formParams;
    private final Map<String, List<String>> allParams;

    private RequestParams(
            Map<String, List<String>> queryParams,
            Map<String, List<String>> formParams,
            Map<String, List<String>> allParams) {
        this.queryParams = queryParams;
        this.formParams = formParams;
        this.allParams = allParams;
    }

    /**
     * Creates the request parameters for the given session.
     *
     * <p>NanoHTTPD only decodes the query string into {@link IHTTPSession#getParameters()}. POST
     * bodies have to be consumed and decoded by the handler, which is what this method expects in
     * {@code body} (consuming it also keeps keep-alive connections usable).
     *
     * @param session the session that has the request
     * @param body the (raw urlencoded) request body, may be empty
     * @return the request parameters
     */
    static RequestParams of(IHTTPSession session, String body) {
        Map<String, List<String>> query = session.getParameters();
        Map<String, List<String>> form = Map.of();
        if (session.getMethod() == Method.POST && isFormUrlEncoded(session)) {
            form = decode(body);
        }
        return new RequestParams(query, form, merge(query, form));
    }

    /**
     * Gets the first value of the given parameter, no matter where it was sent in.
     *
     * @param param the parameter name
     * @return the first value, or {@code null} if the parameter is not present
     */
    String first(String param) {
        return first(allParams, param);
    }

    /**
     * Gets the first value of the given parameter with respect to the given source.
     *
     * @param source where the parameter should have been sent in
     * @param param the parameter name
     * @return the first value, or {@code null} if the parameter is not present in that source
     */
    String first(RequestCondition.Source source, String param) {
        switch (source) {
            case QUERY:
                return first(queryParams, param);
            case FORM:
                return first(formParams, param);
            default:
                return first(allParams, param);
        }
    }

    private static String first(Map<String, List<String>> params, String param) {
        List<String> values = params.get(param);
        if (values == null || values.isEmpty()) {
            return null;
        }
        return values.get(0);
    }

    /**
     * Checks if any parameter value of the request matches the given predicate.
     *
     * @param predicate the predicate to match the values against
     * @return {@code true} if any value matches, {@code false} otherwise
     */
    boolean anyValue(Predicate<String> predicate) {
        for (List<String> values : allParams.values()) {
            for (String value : values) {
                if (predicate.test(value)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isFormUrlEncoded(IHTTPSession session) {
        String contentType = session.getHeaders().get(CONTENT_TYPE);
        if (contentType == null) {
            return false;
        }
        int typeEnd = contentType.indexOf(';');
        String type = typeEnd >= 0 ? contentType.substring(0, typeEnd) : contentType;
        return FORM_URL_ENCODED.equalsIgnoreCase(type.trim());
    }

    /**
     * Decodes urlencoded parameters the same way NanoHTTPD does.
     *
     * @param encoded the raw urlencoded parameter string, may be {@code null}
     * @return the decoded parameters
     */
    private static Map<String, List<String>> decode(String encoded) {
        Map<String, List<String>> params = new HashMap<>();
        if (encoded == null) {
            return params;
        }
        StringTokenizer pairs = new StringTokenizer(encoded.trim(), "&");
        while (pairs.hasMoreTokens()) {
            String pair = pairs.nextToken();
            int sep = pair.indexOf('=');
            String name;
            String value;
            if (sep >= 0) {
                name = decodePercent(pair.substring(0, sep)).trim();
                value = decodePercent(pair.substring(sep + 1));
            } else {
                name = decodePercent(pair).trim();
                value = "";
            }
            params.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
        }
        return params;
    }

    private static String decodePercent(String str) {
        return URLDecoder.decode(str, StandardCharsets.UTF_8);
    }

    /**
     * Combines the query string and body parameters, the query string values come first.
     *
     * @param query the query string parameters
     * @param form the body parameters
     * @return all parameters
     */
    private static Map<String, List<String>> merge(
            Map<String, List<String>> query, Map<String, List<String>> form) {
        if (form.isEmpty()) {
            return query;
        }
        Map<String, List<String>> all = new HashMap<>();
        query.forEach((name, values) -> all.put(name, new ArrayList<>(values)));
        form.forEach(
                (name, values) -> all.computeIfAbsent(name, k -> new ArrayList<>()).addAll(values));
        return all;
    }
}
