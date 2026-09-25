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

import java.util.Objects;
import java.util.function.Predicate;

/**
 * A condition on the parameters of a request, as used by {@link
 * UrlParamValueHandler.Builder#when(RequestCondition...)}.
 *
 * <p>A condition is created for a single parameter and then completed with an expected value:
 *
 * <pre>{@code
 * param("username").is("admin' OR '1'='1")
 * }</pre>
 *
 * <p>Conditions can be combined, all of them have to match:
 *
 * <pre>{@code
 * param("username").is("admin' OR '1'='1").and(param("password").is("x"))
 * }</pre>
 *
 * <p>Only the first value of a parameter is considered, which is what SQL injection payloads
 * require.
 *
 * @see #param(String)
 * @see #queryParam(String)
 * @see #formParam(String)
 */
public class RequestCondition {

    /** The places a parameter can be sent in. */
    enum Source {
        /** Query string or body parameters, or both. */
        ANY,
        /** Query string parameters only, i.e., the parameters of a GET request. */
        QUERY,
        /** {@code application/x-www-form-urlencoded} body parameters only, i.e., of a POST. */
        FORM
    }

    private final Source source;
    private final String param;
    private final Predicate<String> valuePredicate;
    private final RequestCondition[] parts;

    private RequestCondition(Source source, String param, Predicate<String> valuePredicate) {
        this.source = source;
        this.param = param;
        this.valuePredicate = valuePredicate;
        this.parts = null;
    }

    private RequestCondition(RequestCondition... parts) {
        this.source = null;
        this.param = null;
        this.valuePredicate = null;
        this.parts = parts;
    }

    /**
     * Creates a condition on a parameter, no matter if it was sent in the query string or the body.
     *
     * <p>The condition matches if the parameter is present, unless it is completed with an
     * expectation, e.g., {@link #is(String)}.
     *
     * @param name the parameter name
     * @return the condition
     */
    public static RequestCondition param(String name) {
        return reference(Source.ANY, name);
    }

    /**
     * Creates a condition on a query string (GET) parameter.
     *
     * @param name the parameter name
     * @return the condition
     */
    public static RequestCondition queryParam(String name) {
        return reference(Source.QUERY, name);
    }

    /**
     * Creates a condition on a {@code application/x-www-form-urlencoded} body (POST) parameter.
     *
     * @param name the parameter name
     * @return the condition
     */
    public static RequestCondition formParam(String name) {
        return reference(Source.FORM, name);
    }

    private static RequestCondition reference(Source source, String name) {
        Objects.requireNonNull(name, "name must not be null");
        return new RequestCondition(source, name, null);
    }

    /**
     * Expects the first value of the parameter to be equal to the given value.
     *
     * @param value the expected value
     * @return the completed condition
     */
    public RequestCondition is(String value) {
        Objects.requireNonNull(value, "value must not be null");
        return withValuePredicate(value::equals);
    }

    /**
     * Expects the parameter to be present with a first value different to the given value.
     *
     * @param value the value which must not be sent
     * @return the completed condition
     */
    public RequestCondition isNot(String value) {
        Objects.requireNonNull(value, "value must not be null");
        return withValuePredicate(v -> !value.equals(v));
    }

    /**
     * Expects the first value of the parameter to match the given predicate.
     *
     * @param predicate the predicate the value has to match
     * @return the completed condition
     */
    public RequestCondition matches(Predicate<String> predicate) {
        Objects.requireNonNull(predicate, "predicate must not be null");
        return withValuePredicate(predicate);
    }

    private RequestCondition withValuePredicate(Predicate<String> predicate) {
        if (parts != null) {
            throw new IllegalStateException("a combined condition must not be completed");
        }
        return new RequestCondition(source, param, predicate);
    }

    /**
     * Combines this condition with another one, both have to match.
     *
     * @param other the other condition
     * @return the combined condition
     */
    public RequestCondition and(RequestCondition other) {
        Objects.requireNonNull(other, "other must not be null");
        return new RequestCondition(this, other);
    }

    static RequestCondition allOf(RequestCondition... conditions) {
        Objects.requireNonNull(conditions, "conditions must not be null");
        if (conditions.length == 0) {
            throw new IllegalArgumentException("at least one condition must be provided");
        }
        if (conditions.length == 1) {
            return conditions[0];
        }
        return new RequestCondition(conditions);
    }

    boolean matches(RequestParams params) {
        if (parts != null) {
            for (RequestCondition part : parts) {
                if (!part.matches(params)) {
                    return false;
                }
            }
            return true;
        }
        String value = params.first(source, param);
        if (valuePredicate == null) {
            return value != null;
        }
        return value != null && valuePredicate.test(value);
    }
}
