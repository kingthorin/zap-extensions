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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascanrules.sqli.ParameterContext.ValueShape;

/** Pure-logic unit test for {@link SqliContextAnalyzer} -- no HTTP server needed. */
class SqliContextAnalyzerUnitTest {

    @Test
    void shouldInferNumericContextFromDigitsOnlyValue() throws Exception {
        // When
        ParameterContext context = SqliContextAnalyzer.analyze("id", "42", new HttpMessage());
        // Then
        assertThat(context.isNumericContext, is(true));
        assertThat(context.isStringLiteralContext, is(false));
    }

    @Test
    void shouldInferStringContextFromNonNumericValue() throws Exception {
        // When
        ParameterContext context = SqliContextAnalyzer.analyze("id", "jsmith", new HttpMessage());
        // Then
        assertThat(context.isNumericContext, is(false));
        assertThat(context.isStringLiteralContext, is(true));
    }

    @ParameterizedTest
    @CsvSource({
        "42, NUMERIC",
        "2010-02-02, DATE",
        "msgid, IDENTIFIER",
        "user.name, IDENTIFIER",
        "hello world, TEXT",
        "a+b, TEXT"
    })
    void shouldClassifyTheValueShape(String value, ValueShape expected) {
        // When
        ParameterContext context = SqliContextAnalyzer.analyze("q", value, new HttpMessage());
        // Then
        assertThat(context.getValueShape(), is(expected));
    }

    @ParameterizedTest
    @CsvSource({
        "orderby, msgid, true",
        "SortBy, title, true",
        "sort, 1, true",
        "q, name DESC, true",
        "q, asc, true",
        "q, msgid, false",
        "border, msgid, false",
        "username, jsmith, false"
    })
    void shouldHintOrderByFromTheNameOrASortDirection(String name, String value, boolean hint) {
        // When
        ParameterContext context = SqliContextAnalyzer.analyze(name, value, new HttpMessage());
        // Then
        assertThat(context.isOrderByHint(), is(hint));
    }

    @Test
    void shouldRunOrderByAheadOfTheOtherDifferentialTechniquesOnASortParameter() {
        // When
        ParameterContext context = SqliContextAnalyzer.analyze("sort", "msgid", new HttpMessage());
        // Then
        assertThat(
                context.estimateProbabilityFor("ORDERBY"),
                is(greaterThan(context.estimateProbabilityFor("ERROR"))));
        assertThat(
                context.estimateProbabilityFor("ORDERBY"),
                is(greaterThan(context.estimateProbabilityFor("UNION"))));
    }

    @ParameterizedTest
    @CsvSource(
            value = {
                "id|42|\"\"",
                "d|2010-02-02|\"\"",
                "sort|msgid|\"\"",
                "user|jsmith|'",
                "q|a b|'"
            },
            delimiter = '|',
            quoteCharacter = '"')
    void shouldGuessTheClosingFromTheValueShape(String name, String value, String closing) {
        // When
        ParameterContext context = SqliContextAnalyzer.analyze(name, value, new HttpMessage());
        // Then
        assertThat(context.getLearnedClosing(), is(nullValue()));
        assertThat(context.getGuessedClosing(), is(equalTo(closing)));
    }

    @Test
    void shouldPreferTheFirstLearnedClosingOverTheGuess() {
        // Given
        ParameterContext context = SqliContextAnalyzer.analyze("id", "42", new HttpMessage());
        // When
        context.learnClosing("'");
        context.learnClosing("");
        // Then
        assertThat(context.getLearnedClosing(), is(equalTo("'")));
        assertThat(context.getGuessedClosing(), is(equalTo("'")));
    }
}
