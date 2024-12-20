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
import org.zaproxy.zap.testutils.TestUtils;

/* Unit Tests for {@code ClientSideComponent}
 * SoretedSets are used for compareTo testing
 */
class ClientSideComponentUnitTest extends TestUtils {

    private static final String EXAMPLE_URL = "https://example.com";

    @BeforeAll
    static void init() {
        mockMessages(new ExtensionClientIntegration());
    }

    // TODO remove
    // typeForDisplay, href, text, id, tagName, tagType, formId
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
}
