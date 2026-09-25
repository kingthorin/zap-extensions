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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.zaproxy.zap.testutils.RequestCondition.formParam;
import static org.zaproxy.zap.testutils.RequestCondition.param;
import static org.zaproxy.zap.testutils.RequestCondition.queryParam;

import fi.iki.elonen.NanoHTTPD;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests and usage examples for {@link UrlParamValueHandler}, showing how WAVSEP-style SQL
 * injection scenarios are expressed without writing a custom {@link NanoServerHandler}.
 */
class UrlParamValueHandlerUnitTest {

    private HTTPDTestServer server;
    private String baseUrl;
    private final HttpClient client = HttpClient.newHttpClient();

    @BeforeEach
    void setUp() throws IOException {
        server = new HTTPDTestServer(0);
        server.start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);
        baseUrl = "http://localhost:" + server.getListeningPort();
    }

    @AfterEach
    void tearDown() {
        server.stop();
    }

    private HttpResponse<String> get(String uriAndQuery) throws Exception {
        HttpRequest request =
                HttpRequest.newBuilder(URI.create(baseUrl + uriAndQuery)).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> postForm(String path, String formBody) throws Exception {
        HttpRequest request =
                HttpRequest.newBuilder(URI.create(baseUrl + path))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(formBody))
                        .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void shouldMatchMultipleParamConditions() throws Exception {
        // Given
        server.addHandler(
                UrlParamValueHandler.builder()
                        .targetParam("username")
                        .when(
                                param("username")
                                        .is("admin' OR '1'='1")
                                        .and(param("password").is("x")))
                        .thenReturnHtml("hello admin")
                        .fallbackHtmlResponse("login failed")
                        .build());

        // When / Then
        assertThat(get("/?username=admin'%20OR%20'1'%3D'1&password=x").body(), is("hello admin"));
        assertThat(get("/?username=admin'%20OR%20'1'%3D'1&password=y").body(), is("login failed"));
        assertThat(get("/?username=admin&password=x").body(), is("login failed"));
    }

    @Test
    void shouldReturnStatusCodeHeadersAndBody() throws Exception {
        // Given
        server.addHandler(
                UrlParamValueHandler.builder()
                        .targetParam("id")
                        .when(param("id").is("1'"))
                        .withStatus(500)
                        .withHeader("X-SQL-Error", "true")
                        .thenReturn("You have an error in your SQL syntax")
                        .when(param("id").is("json"))
                        .thenReturnJson("{\"users\": []}")
                        .fallbackHtmlResponse("normal")
                        .build());

        // When
        HttpResponse<String> error = get("/?id=1%27");
        HttpResponse<String> json = get("/?id=json");
        HttpResponse<String> normal = get("/?id=1");

        // Then
        assertThat(error.statusCode(), is(500));
        assertThat(error.headers().firstValue("X-SQL-Error").orElse(""), is("true"));
        assertThat(error.body(), is("You have an error in your SQL syntax"));
        assertThat(json.headers().firstValue("Content-Type").orElse(""), containsString("json"));
        assertThat(json.body(), is("{\"users\": []}"));
        assertThat(normal.statusCode(), is(200));
        assertThat(normal.body(), is("normal"));
    }

    @Test
    void shouldMatchPostFormParams() throws Exception {
        // Given
        server.addHandler(
                UrlParamValueHandler.builder()
                        .targetParam("username")
                        .when(formParam("username").is("admin' OR '1'='1"))
                        .thenReturnHtml("bypass")
                        .fallbackHtmlResponse("denied")
                        .build());

        // When / Then
        assertThat(
                postForm("/login", "username=admin'+OR+'1'%3D'1&password=x").body(), is("bypass"));
        assertThat(postForm("/login", "username=admin&password=x").body(), is("denied"));
    }

    @Test
    void shouldTellQueryAndFormParamsApart() throws Exception {
        // Given
        server.addHandler(
                UrlParamValueHandler.builder()
                        .targetParam("id")
                        .when(queryParam("id").is("1"))
                        .thenReturnHtml("query")
                        .when(formParam("id").is("2"))
                        .thenReturnHtml("form")
                        .fallbackHtmlResponse("none")
                        .build());

        // When / Then
        assertThat(get("/?id=1").body(), is("query"));
        assertThat(postForm("/?id=1", "id=2").body(), is("query"));
        assertThat(postForm("/", "id=2").body(), is("form"));
        assertThat(get("/?id=2").body(), is("none"));
        assertThat(postForm("/", "id=1").body(), is("none"));
    }

    @Test
    void shouldActAsBooleanOracle() throws Exception {
        // Given
        server.addHandler(
                UrlParamValueHandler.builder()
                        .targetParam("id")
                        .booleanOracle("users found", "no users")
                        .build());

        // When / Then
        assertThat(get("/?id=1%20AND%201%3D1").body(), is("users found"));
        assertThat(get("/?id=1%20AND%201%3D2").body(), is("no users"));
        assertThat(get("/?id=1%20AND%20'1'%3D'1").body(), is("users found"));
        assertThat(get("/?id=1").body(), is("no users"));
    }

    @Test
    void shouldActAsErrorOracle() throws Exception {
        // Given
        server.addHandler(
                UrlParamValueHandler.builder()
                        .targetParam("id")
                        .fallbackHtmlResponse("normal")
                        .errorOracle("SQL syntax error")
                        .build());

        // When / Then
        assertThat(get("/?id=1").body(), is("normal"));
        assertThat(get("/?id=1%27").statusCode(), is(200));
        assertThat(get("/?id=1%27").body(), is("SQL syntax error"));
    }

    @Test
    void shouldActAsErrorOracleWithServerErrorCode() throws Exception {
        // Given
        server.addHandler(
                UrlParamValueHandler.builder()
                        .targetParam("id")
                        .fallbackHtmlResponse("normal")
                        .errorOracle(500, "SQL syntax error")
                        .build());

        // When
        HttpResponse<String> response = get("/?id=1%27");

        // Then
        assertThat(response.statusCode(), is(500));
        assertThat(response.body(), is("SQL syntax error"));
    }

    @Test
    void shouldActAsLoginBypassOracle() throws Exception {
        // Given
        server.addHandler(
                UrlParamValueHandler.builder()
                        .targetParam("username")
                        .loginBypassOracle("login success", "login failed")
                        .build());

        // When / Then
        assertThat(postForm("/login", "username=admin&password=x").body(), is("login failed"));
        assertThat(postForm("/login", "username=admin'--&password=x").body(), is("login success"));
        assertThat(get("/?username=admin'%20OR%20'1'%3D'1&password=x").body(), is("login success"));
    }

    @Test
    void shouldReflectPayloadAndDiffBodies() throws Exception {
        // Given (handlers are matched in order, so the more specific path comes first)
        server.addHandler(
                UrlParamValueHandler.builder()
                        .targetPath("/diff")
                        .targetParam("id")
                        .bodyDiff("clean", "dirty")
                        .build());
        server.addHandler(
                UrlParamValueHandler.builder().targetParam("q").reflectedPayload("[", "]").build());

        // When / Then
        assertThat(get("/?q=hello").body(), is("[hello]"));
        assertThat(get("/diff?id=1").body(), is("clean"));
        assertThat(get("/diff?id=1%27").body(), is("dirty"));
    }

    @Test
    void shouldReturnSequencedBodiesAndCountRequests() throws Exception {
        // Given
        UrlParamValueHandler handler =
                UrlParamValueHandler.builder()
                        .targetParam("id")
                        .when(param("id").is("1"))
                        .thenReturnSequence("first", "second")
                        .fallbackHtmlResponse("other")
                        .build();
        server.addHandler(handler);

        // When
        HttpResponse<String> first = get("/?id=1");
        HttpResponse<String> second = get("/?id=1");
        HttpResponse<String> third = get("/?id=1");
        get("/?id=2");

        // Then
        assertThat(first.body(), is("first"));
        assertThat(second.body(), is("second"));
        assertThat(third.body(), is("second"));
        assertThat(handler.getRequestCount(), is(4));
        assertThat(handler.getActualParamValues(), contains("1", "1", "1", "2"));
    }

    @Test
    void shouldSupportTheLegacySingleParamApi() throws Exception {
        // Given
        UrlParamValueHandler handler =
                UrlParamValueHandler.builder()
                        .targetParam("param")
                        .whenParamValueIs("test")
                        .thenReturnHtml("normal response")
                        .whenParamValueIs("'")
                        .thenReturnHtml("SQL error")
                        .build();
        server.addHandler(handler);

        // When
        HttpResponse<String> normal = get("/?param=test");
        HttpResponse<String> error = get("/?param=%27");
        HttpResponse<String> other = get("/?param=unknown");

        // Then
        assertThat(normal.body(), is("normal response"));
        assertThat(error.body(), is("SQL error"));
        assertThat(other.body(), is(""));
        assertThat(handler.getExpectedParamValues(), containsInAnyOrder("test", "'"));
        assertThat(handler.getActualParamValues(), contains("test", "'", "unknown"));
    }
}
