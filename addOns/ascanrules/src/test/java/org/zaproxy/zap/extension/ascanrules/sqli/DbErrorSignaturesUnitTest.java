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
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.ascanrules.sqli.DbErrorSignatures.Dbms;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/** Pure-logic unit test for {@link DbErrorSignatures} -- no HTTP server needed. */
class DbErrorSignaturesUnitTest {

    @Test
    void shouldIdentifyMySqlFromRealErrorText() {
        // Given
        String body = "<html>Warning: You have an error in your SQL syntax; check the manual";
        // When
        Optional<Dbms> result = DbErrorSignatures.identify(body);
        // Then
        assertThat(result.isPresent(), is(true));
        assertThat(result.get(), is(equalTo(Dbms.MYSQL)));
    }

    @Test
    void shouldIdentifyOracleFromRealErrorText() {
        // Given
        String body = "ORA-00933: SQL command not properly ended";
        // When
        Optional<Dbms> result = DbErrorSignatures.identify(body);
        // Then
        assertThat(result.isPresent(), is(true));
        assertThat(result.get(), is(equalTo(Dbms.ORACLE)));
    }

    /** The corpus's sqlite-error-in-500 shape: a raw engine message with no driver prefix. */
    @Test
    void shouldIdentifySqliteFromRawSyntaxErrorText() {
        // Given
        String body = "<html>Error executing statement: near \"'\": syntax error</html>";
        // When
        Optional<Dbms> result = DbErrorSignatures.identify(body);
        // Then
        assertThat(result.isPresent(), is(true));
        assertThat(result.get(), is(equalTo(Dbms.SQLITE)));
        assertThat(
                result.get().findMatchedFragment(body).orElse(""),
                is(equalTo("near \"'\": syntax error")));
    }

    @Test
    void shouldIdentifyDerbyFromAltoroLoginPageException() {
        // Given -- AltoroJ's login.jsp prints DBUtil.isValidUser's SQLException verbatim, so a lone
        // quote in uid or passw surfaces Derby's parse error in the page body.
        String body =
                "<span id=\"_ctl0__ctl0_Content_Main_message\" style=\"color:#FF0066;"
                        + "font-size:12pt;font-weight:bold;\">Syntax error: Encountered \"<EOF>\""
                        + " at line 1, column 79.</span>";
        // When
        Optional<Dbms> result = DbErrorSignatures.identify(body);
        // Then
        assertThat(result.isPresent(), is(true));
        assertThat(result.get(), is(equalTo(Dbms.DERBY)));
    }

    @Test
    void shouldFallBackToGenericSignature() {
        // Given
        String body = "500 Internal Server Error: java.sql.SQLException: something broke";
        // When
        Optional<Dbms> result = DbErrorSignatures.identify(body);
        // Then
        assertThat(result.isPresent(), is(true));
        assertThat(result.get(), is(equalTo(Dbms.GENERIC)));
    }

    @Test
    void shouldNotMatchOrdinaryPageContent() {
        // Given
        String body = "<html><body>Welcome back, valued customer!</body></html>";
        // When
        Optional<Dbms> result = DbErrorSignatures.identify(body);
        // Then
        assertThat(result.isPresent(), is(false));
    }

    @Test
    void shouldNotMatchNullOrEmptyBody() {
        assertThat(DbErrorSignatures.identify(null).isPresent(), is(false));
        assertThat(DbErrorSignatures.identify("").isPresent(), is(false));
    }

    @Test
    void shouldBeCaseInsensitive() {
        // Given
        String body = "you HAVE AN error in your sql SYNTAX";
        // When
        Optional<Dbms> result = DbErrorSignatures.identify(body);
        // Then
        assertThat(result.isPresent(), is(true));
        assertThat(result.get(), is(equalTo(Dbms.MYSQL)));
    }

    @Test
    void shouldScopeEnginesToTechWithGenericAlwaysIncluded() {
        // Given
        TechSet mySqlOnly = new TechSet(Tech.MySQL);
        // When
        List<Dbms> result = DbErrorSignatures.inTechScope(mySqlOnly);
        // Then
        assertThat(result, hasItem(Dbms.MYSQL));
        assertThat(result, hasItem(Dbms.GENERIC));
        assertThat(result, not(hasItem(Dbms.ORACLE)));
    }

    @Test
    void shouldReturnEveryEngineWhenScopeIsNull() {
        // When
        List<Dbms> result = DbErrorSignatures.inTechScope(null);
        // Then
        assertThat(result, containsInAnyOrder(Dbms.values()));
    }
}
