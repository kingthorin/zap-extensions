/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;

import fi.iki.elonen.NanoHTTPD;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.regex.Pattern;

/**
 * Simplifies simulation of server responses for use cases, where the attack is based on URL or body
 * parameter values, e.g., SQL injection.
 *
 * <p>Example usage with a single parameter:
 *
 * <pre>{@code
 * nano.addHandler(UrlParamValueHandler.builder()
 *             .targetParam("topic")
 *             .whenParamValueIs("cats' --").thenReturnHtml("A, B")
 *             .whenParamValueIs("cats' AND '1'='1' --").thenReturnHtml("A, B")
 *             .whenParamValueIs("cats' AND '1'='2' --").thenReturnHtml("")
 *             .build()
 *     );
 * }</pre>
 *
 * <p>Multiple parameters are supported, all conditions have to match:
 *
 * <pre>{@code
 * import static org.zaproxy.zap.testutils.RequestCondition.param;
 *
 * nano.addHandler(UrlParamValueHandler.builder()
 *             .targetParam("username")
 *             .when(param("username").is("admin' OR '1'='1").and(param("password").is("x")))
 *                 .thenReturnHtml("hello admin")
 *             .build()
 *     );
 * }</pre>
 *
 * <p>The response of a condition can carry a status code, headers and any body (HTML, plain text or
 * JSON):
 *
 * <pre>{@code
 * import static org.zaproxy.zap.testutils.RequestCondition.queryParam;
 *
 * nano.addHandler(UrlParamValueHandler.builder()
 *             .targetParam("id")
 *             .when(queryParam("id").is("1'"))
 *                 .withStatus(500)
 *                 .withHeader("X-SQL-Error", "true")
 *                 .thenReturn("You have an error in your SQL syntax")
 *             .build()
 *     );
 * }</pre>
 *
 * <p>Common SQL injection oracles can each be configured with a single call, see {@link
 * Builder#booleanOracle(String, String)}, {@link Builder#errorOracle(String)}, {@link
 * Builder#loginBypassOracle(String, String)}, {@link Builder#reflectedPayload(String, String)} and
 * {@link Builder#bodyDiff(String, String)}:
 *
 * <pre>{@code
 * nano.addHandler(UrlParamValueHandler.builder()
 *             .targetParam("id")
 *             .booleanOracle("users found", "no users")
 *             .build()
 *     );
 * }</pre>
 *
 * <p>Query string (GET) as well as {@code application/x-www-form-urlencoded} body (POST) parameters
 * are supported by {@link RequestCondition#param(String)}, {@link
 * RequestCondition#queryParam(String)} and {@link RequestCondition#formParam(String)}.
 *
 * <p>If not overridden by corresponding builder functions, the following defaults apply:
 *
 * <ul>
 *   <li>Handler "listens" for "/" URL path
 *   <li>Handler returns an empty default response for all requests which do not match a condition
 *   <li>Responses have HTTP status OK and MIME type "text/html"
 * </ul>
 *
 * <p>For anything more exotic, extend {@link NanoServerHandler} directly.
 */
public class UrlParamValueHandler extends NanoServerHandler {
    private static final String DEFAULT_RESPONSE = "";

    // ponytail: these payload markers are heuristics which cover the common WAVSEP and ZAP SQL
    // injection payloads; use when(...) rules with exact values for anything else.
    private static final Pattern TRUTHY_MARKER = Pattern.compile("1\\s*=\\s*1|'1'\\s*=\\s*'1'?");
    private static final Pattern FALSY_MARKER = Pattern.compile("1\\s*=\\s*2|'1'\\s*=\\s*'2'?");
    private static final Pattern LOGIN_BYPASS_MARKER =
            Pattern.compile("--|#|/\\*|\\b(and|or)\\b", Pattern.CASE_INSENSITIVE);

    private final String targetParam;
    private final List<Rule> rules;
    private final Set<String> expectedParamValues;
    private final ResponseSpec errorOracle;
    private final BiFunction<RequestParams, String, ResponseSpec> fallback;
    private final List<String> actualParamValues;
    private int requestCount;

    private UrlParamValueHandler(
            String targetPath,
            String targetParam,
            List<Rule> rules,
            Set<String> expectedParamValues,
            ResponseSpec errorOracle,
            BiFunction<RequestParams, String, ResponseSpec> fallback) {
        super(targetPath);
        this.targetParam = targetParam;
        this.rules = rules;
        this.expectedParamValues = expectedParamValues;
        this.errorOracle = errorOracle;
        this.fallback = fallback;
        this.actualParamValues = new ArrayList<>();
    }

    @Override
    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
        // Consume the body of POST requests (also required to keep keep-alive connections usable,
        // NanoHTTPD does not consume it).
        String body = session.getMethod() == NanoHTTPD.Method.POST ? getBody(session) : "";
        RequestParams params = RequestParams.of(session, body);
        String actualParamValue = params.first(targetParam);
        actualParamValues.add(actualParamValue);
        requestCount++;

        for (Rule rule : rules) {
            if (rule.matches(params, targetParam)) {
                return rule.respond(params).toResponse();
            }
        }
        if (errorOracle != null && looksLikeSqlError(actualParamValue)) {
            return errorOracle.toResponse();
        }
        return fallback.apply(params, targetParam).toResponse();
    }

    /**
     * Creates a builder for creating a {@link UrlParamValueHandler}
     *
     * @return a new Builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Gets all parameter values which have been processed by this handler
     *
     * @return a list of all actual parameter values
     */
    public List<String> getActualParamValues() {
        return new ArrayList<>(actualParamValues);
    }

    /**
     * Gets the number of requests which have been processed by this handler, no matter if they
     * matched a condition or not.
     *
     * @return the number of requests
     */
    public int getRequestCount() {
        return requestCount;
    }

    /**
     * Gets all parameter values for which a response have been prepared by calling {@link
     * Builder#whenParamValueIs(String)}
     *
     * @return a set of all expected parameter values
     */
    public Set<String> getExpectedParamValues() {
        return new LinkedHashSet<>(expectedParamValues);
    }

    public static class Builder {
        private String targetPath = "/";
        private String targetParam;
        private final List<Rule> rules = new ArrayList<>();
        private final Set<String> expectedParamValues = new LinkedHashSet<>();
        private ResponseSpec errorOracle;
        private BiFunction<RequestParams, String, ResponseSpec> fallback =
                (params, param) -> response(200, NanoHTTPD.MIME_HTML, DEFAULT_RESPONSE);

        private Builder() {}

        /**
         * Overrides the default URL path for which the created handler is to return responses
         * (default: "/").
         *
         * @param targetPath the URL path
         * @return a Builder
         */
        public Builder targetPath(String targetPath) {
            Objects.requireNonNull(targetPath, "targetPath must not be null");
            this.targetPath = targetPath;
            return this;
        }

        /**
         * Sets the name of the param which will hold the attack payload.
         *
         * @param targetParam the param name
         * @return a Builder
         */
        public Builder targetParam(String targetParam) {
            Objects.requireNonNull(targetParam, "targetParam must not be null");
            this.targetParam = targetParam;
            return this;
        }

        /**
         * Defines a parameter value for which a specific response should be returned.
         *
         * @param paramValue the param value
         * @return a ResponseBuilder for building the actual response
         */
        public ResponseBuilder whenParamValueIs(String paramValue) {
            Objects.requireNonNull(paramValue, "paramValue must not be null");
            return new ResponseBuilder(this, paramValue, null);
        }

        /**
         * Defines conditions on request parameters for which a specific response should be
         * returned. All given conditions have to match, conditions on multiple parameters can be
         * combined, e.g.:
         *
         * <pre>{@code
         * .when(param("username").is("admin' OR '1'='1").and(param("password").is("x")))
         *     .thenReturnHtml("hello admin")
         * }</pre>
         *
         * @param conditions the conditions which have to match, at least one
         * @return a ResponseBuilder for building the actual response
         * @see RequestCondition
         */
        public ResponseBuilder when(RequestCondition... conditions) {
            return new ResponseBuilder(this, null, RequestCondition.allOf(conditions));
        }

        /**
         * Overrides the default content of the fallback response message which is returned for all
         * requests which are not specified via {@link #whenParamValueIs(String)} or {@link
         * #when(RequestCondition...)} (default: "").
         *
         * @param content the content in fallback response
         * @return a Builder
         */
        public Builder fallbackHtmlResponse(String content) {
            Objects.requireNonNull(content, "content must not be null");
            this.fallback = (params, param) -> response(200, NanoHTTPD.MIME_HTML, content);
            return this;
        }

        /**
         * Makes the handler act as a boolean-based SQL injection oracle: requests whose target
         * parameter value contains a truthy payload marker (e.g. {@code 1=1} or {@code '1'='1'})
         * get the {@code trueBody}, all other requests (including the baseline request) get the
         * {@code falseBody}.
         *
         * <p>The markers are heuristics covering the common WAVSEP/ZAP payloads, use {@link
         * #when(RequestCondition...)} with exact payload values if that is not enough.
         *
         * @param trueBody the body for truthy payloads
         * @param falseBody the body for falsy payloads
         * @return a Builder
         */
        public Builder booleanOracle(String trueBody, String falseBody) {
            Objects.requireNonNull(trueBody, "trueBody must not be null");
            Objects.requireNonNull(falseBody, "falseBody must not be null");
            this.fallback =
                    (params, param) ->
                            response(
                                    200,
                                    NanoHTTPD.MIME_HTML,
                                    isTruthy(params.first(param)) ? trueBody : falseBody);
            return this;
        }

        /**
         * Makes the handler respond with an SQL error text for any request whose target parameter
         * value contains a quote, and with the fallback response (see {@link
         * #fallbackHtmlResponse(String)}) for all other requests. The response has HTTP status OK,
         * use {@link #errorOracle(int, String)} for e.g. a 500 response.
         *
         * @param errorText the text of the SQL error
         * @return a Builder
         */
        public Builder errorOracle(String errorText) {
            return errorOracle(200, errorText);
        }

        /**
         * Makes the handler respond with an SQL error text for any request whose target parameter
         * value contains a quote, and with the fallback response (see {@link
         * #fallbackHtmlResponse(String)}) for all other requests.
         *
         * @param statusCode the HTTP status code of the error response, e.g. 500
         * @param errorText the text of the SQL error
         * @return a Builder
         */
        public Builder errorOracle(int statusCode, String errorText) {
            Objects.requireNonNull(errorText, "errorText must not be null");
            this.errorOracle = response(statusCode, NanoHTTPD.MIME_HTML, errorText);
            return this;
        }

        /**
         * Makes the handler act as a login bypass oracle: any request with a parameter value which
         * contains a quote together with a SQL comment or boolean operator (e.g. {@code admin' --}
         * or {@code admin' OR '1'='1'}) gets the {@code successBody}, all other requests get the
         * {@code failureBody}.
         *
         * @param successBody the body for a bypassed login
         * @param failureBody the body for a failed login
         * @return a Builder
         */
        public Builder loginBypassOracle(String successBody, String failureBody) {
            Objects.requireNonNull(successBody, "successBody must not be null");
            Objects.requireNonNull(failureBody, "failureBody must not be null");
            this.fallback =
                    (params, param) ->
                            response(
                                    200,
                                    NanoHTTPD.MIME_HTML,
                                    params.anyValue(UrlParamValueHandler::isLoginBypass)
                                            ? successBody
                                            : failureBody);
            return this;
        }

        /**
         * Makes the handler respond with the target parameter value wrapped in the given prefix and
         * suffix, i.e., every payload is reflected in the response body.
         *
         * @param prefix the content before the reflected value
         * @param suffix the content after the reflected value
         * @return a Builder
         */
        public Builder reflectedPayload(String prefix, String suffix) {
            Objects.requireNonNull(prefix, "prefix must not be null");
            Objects.requireNonNull(suffix, "suffix must not be null");
            this.fallback =
                    (params, param) -> {
                        String value = params.first(param);
                        return response(
                                200,
                                NanoHTTPD.MIME_HTML,
                                prefix + (value == null ? "" : value) + suffix);
                    };
            return this;
        }

        /**
         * Makes the handler respond with a different body when the target parameter value contains
         * a quote (i.e., an injection attempt) than for all other requests, so that responses can
         * be told apart based on their body.
         *
         * @param normalBody the body for requests without an injection attempt
         * @param injectedBody the body for requests with an injection attempt
         * @return a Builder
         */
        public Builder bodyDiff(String normalBody, String injectedBody) {
            Objects.requireNonNull(normalBody, "normalBody must not be null");
            Objects.requireNonNull(injectedBody, "injectedBody must not be null");
            this.fallback =
                    (params, param) ->
                            response(
                                    200,
                                    NanoHTTPD.MIME_HTML,
                                    looksLikeSqlError(params.first(param))
                                            ? injectedBody
                                            : normalBody);
            return this;
        }

        /**
         * Creates a {@link UrlParamValueHandler}
         *
         * @return an new handler
         */
        public UrlParamValueHandler build() {
            Objects.requireNonNull(
                    targetParam, "you must specify a targetParam by calling #targetParam()");
            return new UrlParamValueHandler(
                    targetPath, targetParam, rules, expectedParamValues, errorOracle, fallback);
        }
    }

    public static class ResponseBuilder {
        private final Builder builder;

        private final String paramValue;
        private final RequestCondition condition;
        private int statusCode = 200;
        private String mimeType = NanoHTTPD.MIME_HTML;
        private final Map<String, String> headers = new LinkedHashMap<>();

        private ResponseBuilder(Builder builder, String paramValue, RequestCondition condition) {
            this.builder = builder;
            this.paramValue = paramValue;
            this.condition = condition;
        }

        /**
         * Sets the HTTP status code of the response (default: 200).
         *
         * @param statusCode the HTTP status code
         * @return a ResponseBuilder
         */
        public ResponseBuilder withStatus(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        /**
         * Sets the MIME type of the response (default: "text/html").
         *
         * @param mimeType the MIME type
         * @return a ResponseBuilder
         */
        public ResponseBuilder withMimeType(String mimeType) {
            Objects.requireNonNull(mimeType, "mimeType must not be null");
            this.mimeType = mimeType;
            return this;
        }

        /**
         * Adds a header to the response.
         *
         * @param name the header name
         * @param value the header value
         * @return a ResponseBuilder
         */
        public ResponseBuilder withHeader(String name, String value) {
            Objects.requireNonNull(name, "name must not be null");
            Objects.requireNonNull(value, "value must not be null");
            this.headers.put(name, value);
            return this;
        }

        /**
         * Sets the content of the response to be returned for the conditions specified in a
         * previous {@link Builder#whenParamValueIs(String)} or {@link
         * Builder#when(RequestCondition...)} call.
         *
         * <p>The response to be returned will have HTTP status OK and MIME type "text/html", unless
         * overridden with {@link #withStatus(int)} or {@link #withMimeType(String)}.
         *
         * @param htmlContent the content in response
         * @return a Builder
         * @see NanoHTTPD#newFixedLengthResponse(String)
         */
        public Builder thenReturnHtml(String htmlContent) {
            this.mimeType = NanoHTTPD.MIME_HTML;
            return thenReturn(htmlContent);
        }

        /**
         * Sets the content of the response, with MIME type "text/plain".
         *
         * @param text the content in response
         * @return a Builder
         */
        public Builder thenReturnText(String text) {
            this.mimeType = NanoHTTPD.MIME_PLAINTEXT;
            return thenReturn(text);
        }

        /**
         * Sets the content of the response, with MIME type "application/json".
         *
         * @param json the content in response
         * @return a Builder
         */
        public Builder thenReturnJson(String json) {
            this.mimeType = "application/json";
            return thenReturn(json);
        }

        /**
         * Sets the content of the response with the configured status code, MIME type and headers.
         *
         * @param body the content in response
         * @return a Builder
         */
        public Builder thenReturn(String body) {
            ResponseSpec spec = spec(body);
            return commit((params, matchIndex) -> spec);
        }

        /**
         * Sets the content of the response with the given status code.
         *
         * @param statusCode the HTTP status code
         * @param body the content in response
         * @return a Builder
         */
        public Builder thenReturn(int statusCode, String body) {
            this.statusCode = statusCode;
            return thenReturn(body);
        }

        /**
         * Sets a different body for each request matching the conditions, in order. The last body
         * is repeated once all previous ones have been used. Useful for expressing a few sequential
         * cases without writing a custom handler.
         *
         * @param bodies the bodies in the order in which they are returned
         * @return a Builder
         */
        public Builder thenReturnSequence(String... bodies) {
            Objects.requireNonNull(bodies, "bodies must not be null");
            if (bodies.length == 0) {
                throw new IllegalArgumentException("at least one body must be provided");
            }
            List<ResponseSpec> specs = new ArrayList<>(bodies.length);
            for (String body : bodies) {
                specs.add(spec(body));
            }
            return commit(
                    (params, matchIndex) -> specs.get(Math.min(matchIndex, specs.size() - 1)));
        }

        private ResponseSpec spec(String body) {
            return new ResponseSpec(statusCode, mimeType, body, Map.copyOf(headers));
        }

        private Builder commit(BiFunction<RequestParams, Integer, ResponseSpec> responder) {
            builder.rules.add(new Rule(paramValue, condition, responder));
            if (paramValue != null) {
                builder.expectedParamValues.add(paramValue);
            }
            return builder;
        }
    }

    /** A condition together with the response to return when it matches. */
    private static class Rule {
        private final String paramValue;
        private final RequestCondition condition;
        private final BiFunction<RequestParams, Integer, ResponseSpec> responder;
        private int matchCount;

        private Rule(
                String paramValue,
                RequestCondition condition,
                BiFunction<RequestParams, Integer, ResponseSpec> responder) {
            this.paramValue = paramValue;
            this.condition = condition;
            this.responder = responder;
        }

        private boolean matches(RequestParams params, String targetParam) {
            if (paramValue != null) {
                return paramValue.equals(params.first(targetParam));
            }
            return condition.matches(params);
        }

        private ResponseSpec respond(RequestParams params) {
            return responder.apply(params, matchCount++);
        }
    }

    /** The status, MIME type, headers and body of a response. */
    private static class ResponseSpec {
        private final int statusCode;
        private final String mimeType;
        private final String body;
        private final Map<String, String> headers;

        private ResponseSpec(
                int statusCode, String mimeType, String body, Map<String, String> headers) {
            this.statusCode = statusCode;
            this.mimeType = mimeType;
            this.body = body;
            this.headers = headers;
        }

        private NanoHTTPD.Response toResponse() {
            NanoHTTPD.Response.IStatus status = NanoHTTPD.Response.Status.lookup(statusCode);
            if (status == null) {
                status =
                        new NanoHTTPD.Response.IStatus() {
                            @Override
                            public String getDescription() {
                                return statusCode + " Status";
                            }

                            @Override
                            public int getRequestStatus() {
                                return statusCode;
                            }
                        };
            }
            NanoHTTPD.Response response = newFixedLengthResponse(status, mimeType, body);
            headers.forEach(response::addHeader);
            return response;
        }
    }

    private static ResponseSpec response(int statusCode, String mimeType, String body) {
        return new ResponseSpec(statusCode, mimeType, body, Map.of());
    }

    private static boolean looksLikeSqlError(String value) {
        return value != null && (value.contains("'") || value.contains("\""));
    }

    private static boolean isTruthy(String value) {
        return value != null
                && TRUTHY_MARKER.matcher(value).find()
                && !FALSY_MARKER.matcher(value).find();
    }

    private static boolean isLoginBypass(String value) {
        return looksLikeSqlError(value) && LOGIN_BYPASS_MARKER.matcher(value).find();
    }
}
