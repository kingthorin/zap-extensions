/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.client.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientSideComponent.Type;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit Tests for {@code ClientSideComponent} SoretedSets are used for sorting testing */
class ClientSideComponentUnitTest extends TestUtils {

    private static final String EXAMPLE_URL = "https://example.com";
    private static final String ZOO_URL = "https://zoo.example.com";

    @BeforeAll
    static void init() {
        mockMessages(new ExtensionClientIntegration());
    }

    @Test
    void shouldOrderByTypeForDisplayThenHrefThenTextSameHrefs() {
        // Given
        ClientSideComponent one =
                new ClientSideComponent(
                        Map.of(),
                        "",
                        "foo",
                        "",
                        EXAMPLE_URL,
                        "zNotDisplayed",
                        ClientSideComponent.Type.COOKIES,
                        "",
                        -1);
        ClientSideComponent two =
                new ClientSideComponent(
                        Map.of(),
                        "A",
                        "foo",
                        "",
                        EXAMPLE_URL,
                        "zLink",
                        ClientSideComponent.Type.LINK,
                        "",
                        -1);
        ClientSideComponent three =
                new ClientSideComponent(
                        Map.of(),
                        "",
                        "foo",
                        "",
                        EXAMPLE_URL,
                        "aNotDisplayed",
                        ClientSideComponent.Type.COOKIES,
                        "",
                        -1);
        ClientSideComponent four =
                new ClientSideComponent(
                        Map.of(),
                        "A",
                        "foo",
                        "",
                        EXAMPLE_URL,
                        "aLink",
                        ClientSideComponent.Type.LINK,
                        "",
                        -1);
        // When
        SortedSet<ClientSideComponent> sortedComponents =
                new TreeSet<>(Set.of(one, two, three, four));
        // Then
        assertThat(sortedComponents, contains(three, one, four, two));
    }

    @Test
    void shouldOrderByTypeForDisplayThenHrefThenTextDifferentHrefs() {
        // Given
        ClientSideComponent one =
                new ClientSideComponent(
                        Map.of(),
                        "",
                        "foo",
                        "",
                        EXAMPLE_URL,
                        "zNotDisplayed",
                        ClientSideComponent.Type.COOKIES,
                        "",
                        -1);
        ClientSideComponent two =
                new ClientSideComponent(
                        Map.of(),
                        "A",
                        "foo",
                        "",
                        EXAMPLE_URL,
                        "zLink",
                        ClientSideComponent.Type.LINK,
                        "",
                        -1);
        ClientSideComponent three =
                new ClientSideComponent(
                        Map.of(),
                        "",
                        "foo",
                        "",
                        "https://zoo.com",
                        "aNotDisplayed",
                        ClientSideComponent.Type.COOKIES,
                        "",
                        -1);
        ClientSideComponent four =
                new ClientSideComponent(
                        Map.of(),
                        "A",
                        "foo",
                        "",
                        EXAMPLE_URL,
                        "aLink",
                        ClientSideComponent.Type.LINK,
                        "",
                        -1);
        // When
        SortedSet<ClientSideComponent> sortedComponents =
                new TreeSet<>(Set.of(one, two, four, three));
        // Then
        assertThat(sortedComponents, contains(one, three, four, two));
    }

    private static Stream<Arguments> getPathArguments() {
        // The zeroth values should become the last when sorted
        return Stream.of(
                // Length
                Arguments.of(List.of("/aaaa", "/a", "/aa", "/aaa")),
                // Alpha .. gold before golf
                Arguments.of(List.of("/golf", "/a", "/b", "/gold")),
                // Caps then length
                Arguments.of(List.of("/aaa", "/A", "/a", "/aa")));
    }

    @ParameterizedTest
    @MethodSource("getPathArguments")
    void shouldSortSameTypesOnHrefFirst(List<String> paths) {
        // Given
        ClientSideComponent zero = getComponentWithVariedPath(paths.get(0));
        ClientSideComponent one = getComponentWithVariedPath(paths.get(1));
        ClientSideComponent two = getComponentWithVariedPath(paths.get(2));
        ClientSideComponent three = getComponentWithVariedPath(paths.get(3));
        // When
        SortedSet<ClientSideComponent> sortedComponents =
                new TreeSet<>(Set.of(two, one, zero, three));
        // Then
        assertThat(sortedComponents, contains(one, two, three, zero));
    }

    private static ClientSideComponent getComponentWithVariedPath(String pathPart) {
        return new ClientSideComponent(
                Map.of(),
                "A",
                "foo",
                "",
                EXAMPLE_URL + pathPart,
                "aLink",
                ClientSideComponent.Type.LINK,
                "",
                -1);
    }

    private static Stream<Arguments> getTypePairsAndExpectedResult() {
        return Stream.of(
                Arguments.of(Type.BUTTON, Type.BUTTON, 0),
                Arguments.of(Type.BUTTON, Type.SESSIONSTORAGE, -17),
                Arguments.of(Type.COOKIES, Type.BUTTON, 1),
                Arguments.of(null, null, 0),
                Arguments.of(null, Type.BUTTON, -1),
                Arguments.of(Type.COOKIES, null, 1));
    }

    @ParameterizedTest
    @MethodSource("getTypePairsAndExpectedResult")
    void shouldCompareTypeAsExpected(Type first, Type second, int expected) {
        // Given - Note: Types are actually compared by label
        ClientSideComponent one =
                new ClientSideComponent(
                        Map.of(),
                        "tagName",
                        "id",
                        EXAMPLE_URL,
                        EXAMPLE_URL,
                        "text",
                        first,
                        "tagType",
                        -1);
        ClientSideComponent two =
                new ClientSideComponent(
                        Map.of(),
                        "tagName",
                        "id",
                        EXAMPLE_URL,
                        EXAMPLE_URL,
                        "text",
                        second,
                        "tagType",
                        -1);
        // When
        int actual = one.compareTo(two);
        // Then
        assertThat(actual, is(equalTo(expected)));
    }

    private static Stream<Arguments> getUrlPairsAndExpectedResult() {
        return Stream.of(
                Arguments.of(EXAMPLE_URL, EXAMPLE_URL, 0),
                Arguments.of(EXAMPLE_URL, ZOO_URL, -21),
                Arguments.of(ZOO_URL, EXAMPLE_URL, 21),
                Arguments.of(null, null, 0),
                Arguments.of(null, EXAMPLE_URL, -1),
                Arguments.of(EXAMPLE_URL, null, 1));
    }

    @ParameterizedTest
    @MethodSource("getUrlPairsAndExpectedResult")
    void shouldCompareHrefsAsExpected(String first, String second, int expected) {
        // Given
        ClientSideComponent one =
                new ClientSideComponent(
                        Map.of(),
                        "tagName",
                        "id",
                        EXAMPLE_URL,
                        first,
                        "text",
                        Type.BUTTON,
                        "tagType",
                        -1);
        ClientSideComponent two =
                new ClientSideComponent(
                        Map.of(),
                        "tagName",
                        "id",
                        EXAMPLE_URL,
                        second,
                        "text",
                        Type.BUTTON,
                        "tagType",
                        -1);
        // When
        int actual = one.compareTo(two);
        // Then
        assertThat(actual, is(equalTo(expected)));
    }

    @ParameterizedTest
    @MethodSource("getUrlPairsAndExpectedResult") // Re-use, text is text
    void shouldCompareTextAsExpected(String first, String second, int expected) {
        // Given
        ClientSideComponent one =
                new ClientSideComponent(
                        Map.of(),
                        "tagName",
                        "id",
                        EXAMPLE_URL,
                        EXAMPLE_URL,
                        first,
                        Type.BUTTON,
                        "tagType",
                        -1);
        ClientSideComponent two =
                new ClientSideComponent(
                        Map.of(),
                        "tagName",
                        "id",
                        EXAMPLE_URL,
                        EXAMPLE_URL,
                        second,
                        Type.BUTTON,
                        "tagType",
                        -1);
        // When
        int actual = one.compareTo(two);
        // Then
        assertThat(actual, is(equalTo(expected)));
    }

    @ParameterizedTest
    @MethodSource("getUrlPairsAndExpectedResult") // Re-use, text is text
    void shouldCompareIdAsExpected(String first, String second, int expected) {
        // Given
        ClientSideComponent one =
                new ClientSideComponent(
                        Map.of(),
                        "tagName",
                        first,
                        EXAMPLE_URL,
                        EXAMPLE_URL,
                        "text",
                        Type.BUTTON,
                        "tagType",
                        -1);
        ClientSideComponent two =
                new ClientSideComponent(
                        Map.of(),
                        "tagName",
                        second,
                        EXAMPLE_URL,
                        EXAMPLE_URL,
                        "text",
                        Type.BUTTON,
                        "tagType",
                        -1);
        // When
        int actual = one.compareTo(two);
        // Then
        assertThat(actual, is(equalTo(expected)));
    }

    @ParameterizedTest
    @MethodSource("getUrlPairsAndExpectedResult") // Re-use, text is text
    void shouldCompareTagNameAsExpected(String first, String second, int expected) {
        // Given
        ClientSideComponent one =
                new ClientSideComponent(
                        Map.of(),
                        first,
                        "id",
                        EXAMPLE_URL,
                        EXAMPLE_URL,
                        "text",
                        Type.BUTTON,
                        "tagType",
                        -1);
        ClientSideComponent two =
                new ClientSideComponent(
                        Map.of(),
                        second,
                        "id",
                        EXAMPLE_URL,
                        EXAMPLE_URL,
                        "text",
                        Type.BUTTON,
                        "tagType",
                        -1);
        // When
        int actual = one.compareTo(two);
        // Then
        assertThat(actual, is(equalTo(expected)));
    }

    @ParameterizedTest
    @MethodSource("getUrlPairsAndExpectedResult") // Re-use, text is text
    void shouldCompareTagTypeAsExpected(String first, String second, int expected) {
        // Given
        ClientSideComponent one =
                new ClientSideComponent(
                        Map.of(),
                        "tagName",
                        "id",
                        EXAMPLE_URL,
                        EXAMPLE_URL,
                        "text",
                        Type.BUTTON,
                        first,
                        -1);
        ClientSideComponent two =
                new ClientSideComponent(
                        Map.of(),
                        "tagName",
                        "id",
                        EXAMPLE_URL,
                        EXAMPLE_URL,
                        "text",
                        Type.BUTTON,
                        second,
                        -1);
        // When
        int actual = one.compareTo(two);
        // Then
        assertThat(actual, is(equalTo(expected)));
    }

    private static Stream<Arguments> getFormIdPairsAndExpectedResult() {
        return Stream.of(Arguments.of(7, 7, 0), Arguments.of(10, 7, 1), Arguments.of(7, 10, -1));
    }

    @ParameterizedTest
    @MethodSource("getFormIdPairsAndExpectedResult") // Re-use, text is text
    void shouldCompareFormIdAsExpected(int first, int second, int expected) {
        // Given
        ClientSideComponent one =
                new ClientSideComponent(
                        Map.of(),
                        "tagName",
                        "id",
                        EXAMPLE_URL,
                        EXAMPLE_URL,
                        "text",
                        Type.BUTTON,
                        "tagType",
                        first);
        ClientSideComponent two =
                new ClientSideComponent(
                        Map.of(),
                        "tagName",
                        "id",
                        EXAMPLE_URL,
                        EXAMPLE_URL,
                        "text",
                        Type.BUTTON,
                        "tagType",
                        second);
        // When
        int actual = one.compareTo(two);
        // Then
        assertThat(actual, is(equalTo(expected)));
    }
}
