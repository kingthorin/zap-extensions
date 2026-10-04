/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.apache.commons.text.StringEscapeUtils.escapeXml10;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.zaproxy.zap.testutils.RequestCondition.formParam;
import static org.zaproxy.zap.testutils.RequestCondition.param;

import com.strobel.functions.Supplier;
import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import fi.iki.elonen.NanoHTTPD.Response.Status;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.UrlParamValueHandler;

/**
 * Base class for the shared SQL injection scan rule test scenarios.
 *
 * <p>All scenario tests (WAVSEP-inspired boolean/tautology, error-based, union-based, expression
 * evaluation, different-200 responses and the "should not alert" negative cases) live here, so that
 * every concrete rule extending this class is exercised with the exact same set of tests:
 *
 * <ul>
 *   <li>{@link SqlInjectionScanRuleUnitTest} - the generic rule (id 40018)
 *   <li>{@link SqlInjectionScanRule424242UnitTest} - the temporary replacement rule (id 424242)
 * </ul>
 *
 * <p>This is intentionally a side-by-side benchmark rather than a suite that adapts to the rule
 * under test: a scenario may pass for one rule and fail for the other, and such a difference is the
 * signal the comparison is meant to surface. Timing and OOB cases are out of scope.
 *
 * <p>The payload constants referenced from {@link SqlInjectionScanRule} are used as the canonical
 * payload vocabulary; the 424242 rule ports the same payload sets (see {@code
 * BooleanConditionPayloads}).
 */
abstract class SqlInjectionScanRuleTestBase<T extends AbstractAppParamPlugin>
        extends ActiveScannerTest<T> {

    static final List<String> ALL_EXCEPT_GENERIC_SQL_ERRORS =
            List.of(
                    "You have an error in your SQL syntax",
                    "com.mysql.jdbc.exceptions",
                    "org.gjt.mm.mysql",
                    "ODBC driver does not support",
                    "The used SELECT statements have a different number of columns",
                    "You have an error in your SQL syntax",
                    "The used SELECT statements have a different number of columns",
                    "com.microsoft.sqlserver.jdbc",
                    "com.microsoft.jdbc",
                    "com.inet.tds",
                    "com.microsoft.sqlserver.jdbc",
                    "com.ashna.jturbo",
                    "weblogic.jdbc.mssqlserver",
                    "[Microsoft]",
                    "[SQLServer]",
                    "[SQLServer 2000 Driver for JDBC]",
                    "net.sourceforge.jtds.jdbc",
                    "80040e14",
                    "800a0bcd",
                    "80040e57",
                    "ODBC driver does not support",
                    "All queries in an SQL statement containing a UNION operator must have an equal number of expressions in their target lists",
                    "All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists",
                    "oracle.jdbc",
                    "SQLSTATE[HY",
                    "ORA-00933",
                    "ORA-06512",
                    "SQL command not properly ended",
                    "ORA-00942",
                    "ORA-29257",
                    "ORA-00932",
                    "query block has incorrect number of result columns",
                    "ORA-01789",
                    "com.ibm.db2.jcc",
                    "COM.ibm.db2.jdbc",
                    "org.postgresql.util.PSQLException",
                    "org.postgresql",
                    "each UNION query must have the same number of columns",
                    "unterminated quoted string at or near",
                    "syntax error at or near",
                    "com.sybase.jdbc",
                    "net.sourceforge.jtds.jdbc",
                    "com.informix.jdbc",
                    "org.firebirdsql.jdbc",
                    "ids.sql",
                    "org.enhydra.instantdb.jdbc",
                    "jdbc.idb",
                    "interbase.interclient",
                    "org.hsql",
                    "hSql.",
                    "Unexpected token , requires FROM in statement",
                    "Unexpected end of command in statement",
                    "Column count does not match in statement",
                    "Table not found in statement",
                    "Unexpected token:",
                    "Unexpected end of command in statement",
                    "Column count does not match in statement",
                    "sybase.jdbc.sqlanywhere",
                    "com.pointbase.jdbc",
                    "db2j.",
                    "COM.cloudscape",
                    "RmiJdbc.RJDriver",
                    "com.ingres.jdbc",
                    // Deliberately not listed: the pattern "near \".+\": syntax error"
                    // that 40018 carries for SQLite. It is a regex rather than a message a
                    // database sends, and it only ever matched because 40018 compiles its list
                    // as patterns. A real SQLite error (e.g. near "'%'": syntax error) is
                    // covered by SQLITE_ERROR, which the Juice Shop scenario exercises.
                    "SQLITE_ERROR",
                    "SELECTs to the left and right of UNION do not have the same number of result columns");

    static final List<String> GENERIC_SQL_ERRORS =
            List.of(
                    "com.ibatis.common.jdbc",
                    "org.hibernate",
                    "sun.jdbc.odbc",
                    "[ODBC Driver Manager]",
                    "ODBC driver does not support",
                    "System.Data.OleDb",
                    "java.sql.SQLException");

    /**
     * Matches the OR of a tautology payload (e.g. {@code admin' OR '1'='1' -- }), but not the OR
     * inside {@code ORDER BY}, which a plain "contains or" would match as well.
     */
    private static final Pattern SQL_OR_OPERATOR =
            Pattern.compile("\\bor\\b", Pattern.CASE_INSENSITIVE);

    /**
     * The number of requests {@code FiveHundredErrors.shouldAlertIf500OnSingleQuote} is expected to
     * cost. The two rules baseline differently: the generic rule (40018) sends the quote against
     * the base message and stops, spending two requests (control, quote), while the modular rule
     * (424242) also fetches one baseline per parameter, shared by every technique, for three.
     *
     * <p>Stated as an exact count on purpose -- it is the budget regression signal for whichever
     * rule is under test, so raising it hides exactly what it exists to catch.
     *
     * @return the expected number of requests
     */
    protected int expectedRequestsForSingleQuote500() {
        return 2;
    }

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
            case LOW:
                return recommendMax + 1;
            case MEDIUM:
            default:
                return recommendMax + 14;
            case HIGH:
                return recommendMax + 25;
            case INSANE:
                return recommendMax + 7;
        }
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(89)));
        assertThat(wasc, is(equalTo(19)));
        assertThat(tags.size(), is(equalTo(16)));
        assertThat(
                tags.containsKey(CommonAlertTag.API_2023_API10_UNSAFE_CONSUMPTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2025_A05_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_05_SQLI.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.HIPAA.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.PCI_DSS.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.API.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.SEQUENCE.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.API_2023_API10_UNSAFE_CONSUMPTION.getTag()),
                is(equalTo(CommonAlertTag.API_2023_API10_UNSAFE_CONSUMPTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2025_A05_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2025_A05_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INPV_05_SQLI.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_05_SQLI.getValue())));
        assertThat(
                tags.get(CommonAlertTag.HIPAA.getTag()),
                is(equalTo(CommonAlertTag.HIPAA.getValue())));
        assertThat(
                tags.get(CommonAlertTag.PCI_DSS.getTag()),
                is(equalTo(CommonAlertTag.PCI_DSS.getValue())));
    }

    @Test
    void shouldTargetDbTech() {
        // Given
        TechSet techSet = techSet(Tech.Db);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldTargetOracleDbTech() {
        // Given
        TechSet techSet = techSet(Tech.Oracle);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldNotTargetJustNoSqlDbTech() {
        // Given
        TechSet techSet = techSet(Tech.MongoDB, Tech.CouchDB);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    void shouldTargetNoSqlPlusMsSqlDbTech() {
        // Given
        TechSet techSet = techSet(Tech.MongoDB, Tech.MsSQL, Tech.CouchDB);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldTargetDbChildTechs() {
        // Given
        TechSet techSet = techSet(techsOf(Tech.Db));
        techSet.exclude(Tech.Db);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldTargetDbChildTechsWithNonBuiltInTechInstances() {
        // Given
        TechSet techSet = techSet(new Tech(new Tech("Db"), "SomeDb"));
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    void shouldNotTargetNonDbTechs() {
        // Given
        TechSet techSet = techSetWithout(techsOf(Tech.Db));
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    private static String getRawString(Pattern p) {
        return p.toString().replace("\\Q", "").replace("\\E", "");
    }

    @Test
    void allErrorsListShouldBeComplete() {
        Stream.of(SqlInjectionScanRule.RDBMS.values())
                .filter(db -> !db.equals(SqlInjectionScanRule.RDBMS.GENERIC))
                .forEach(
                        db ->
                                db.getErrorPatterns().stream()
                                        .map(SqlInjectionScanRuleTestBase::getRawString)
                                        // 40018 also lists "near \".+\": syntax error" for SQLite.
                                        // That is a regex, not a message a database sends, and it
                                        // only ever matched because 40018 compiles its list as
                                        // patterns, so it is not fed to the rules as response
                                        // content here (see DbErrorSignatures).
                                        .filter(error -> !"near \".+\": syntax error".equals(error))
                                        .forEach(
                                                e ->
                                                        assertThat(
                                                                ALL_EXCEPT_GENERIC_SQL_ERRORS,
                                                                Matchers.hasItem(e))));
    }

    private static void assertNoParams(Alert alert) {
        assertThat(alert.getDescription(), not(containsString("{")));
        assertThat(alert.getOtherInfo(), not(containsString("{")));
    }

    @Test
    void shouldAlertIfSumExpressionsAreSuccessful() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler("/", param, ExpressionBasedHandler.Expression.SUM));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.SUM.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo(ExpressionBasedHandler.Expression.SUM.baseExpression)));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertNoParams(alertsRaised.get(0));
    }

    @Test
    void shouldAlertIfSumExpressionsAreSuccessfulAndReflectedInResponse() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler("/", param, ExpressionBasedHandler.Expression.SUM) {

                    @Override
                    protected String getContent(String value) {
                        return super.getContent(value) + ": " + value;
                    }
                });
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.SUM.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo(ExpressionBasedHandler.Expression.SUM.baseExpression)));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertNoParams(alertsRaised.get(0));
    }

    @Test
    void shouldNotAlertIfSumConfirmationExpressionIsNotSuccessful() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler(
                        "/", param, ExpressionBasedHandler.Expression.SUM, true));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.SUM.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfSumConfirmationExpressionIsNotSuccessfulAndIsReflectedInResponse()
            throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler(
                        "/",
                        param,
                        ExpressionBasedHandler.Expression.SUM,
                        true,
                        ExpressionBasedHandler.Expression.SUM.confirmationExpression));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.SUM.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldAlertIfMultExpressionsAreSuccessful() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler("/", param, ExpressionBasedHandler.Expression.MULT));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.MULT.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo(ExpressionBasedHandler.Expression.MULT.baseExpression)));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertNoParams(alertsRaised.get(0));
    }

    @Test
    void shouldAlertIfMultExpressionsAreSuccessfulAndReflectedInResponse() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler("/", param, ExpressionBasedHandler.Expression.MULT) {

                    @Override
                    protected String getContent(String value) {
                        return super.getContent(value) + ": " + value;
                    }
                });
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.MULT.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo(ExpressionBasedHandler.Expression.MULT.baseExpression)));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertNoParams(alertsRaised.get(0));
    }

    @Test
    void shouldNotAlertIfMultConfirmationExpressionIsNotSuccessful() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler(
                        "/", param, ExpressionBasedHandler.Expression.MULT, true));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.MULT.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfMultConfirmationExpressionIsNotSuccessfulAndReflectedInResponse()
            throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler(
                        "/",
                        param,
                        ExpressionBasedHandler.Expression.MULT,
                        true,
                        ExpressionBasedHandler.Expression.MULT.confirmationExpression));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.MULT.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    static final List<Function<String, String>> ENCODING_FUNCTIONS =
            List.of(
                    SqlInjectionScanRule::getURLEncode,
                    SqlInjectionScanRule::getHTMLEncode,
                    s -> SqlInjectionScanRule.getHTMLEncode(SqlInjectionScanRule.getURLEncode(s)),
                    StringEscapeUtils::escapeXml10,
                    s -> s // Make sure to test for no encoding as well
                    );

    static Stream<Function<String, String>> reflectionEncodings() {
        return ENCODING_FUNCTIONS.stream();
    }

    @Nested
    class BooleanBasedSqlInjection {

        @Test
        void shouldAlertAndTrueMatchesAndFalseDoesNotMatch() throws Exception {
            // Given
            String param = "param";
            String normalValue = "payload";
            String andTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            String andFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(andTrueValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(andFalseValue)
                            .thenReturnHtml(constructReflectedResponse("different response"))
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(actual.getAttack(), is(equalTo(andTrueValue)));
        }

        @Test
        void shouldAlertAndTrueMatchesAndFalseMatchesOrTrueDoesNotMatch() throws Exception {
            // Given
            String param = "param";
            String normalValue = "payload";
            String andTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            String andFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];
            String orTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_OR_TRUE[0];

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(andTrueValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(andFalseValue)
                            .thenReturnHtml(constructReflectedResponse("normal response"))
                            .whenParamValueIs(orTrueValue)
                            .thenReturnHtml("different response")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(actual.getAttack(), is(equalTo(andTrueValue)));
        }

        @Test
        void shouldNotAlertAndTrueMatchesAndFalseMatchesOrTrueMatches() throws Exception {
            // Given
            String param = "param";
            String normalValue = "payload";
            String andTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            String andFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];
            String orTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_OR_TRUE[0];

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(andTrueValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(andFalseValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(orTrueValue)
                            .thenReturnHtml("normal response")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @Test
        void shouldNotAlertAndTrueDoesNotMatch() throws Exception {
            // Given
            String param = "param";
            String normalValue = "payload";
            String andTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml("normal response")
                            .whenParamValueIs(andTrueValue)
                            .thenReturnHtml("different response")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.zap.extension.ascanrules.SqlInjectionScanRuleTestBase#reflectionEncodings")
        void shouldAlertEncodedPayloadReflected(Function<String, String> encodingFunction)
                throws Exception {
            String param = "param";
            String normalValue = "<a>%test"; // Includes characters that will be encoded
            String andTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            String andFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];

            // Set up the positive case where normal and andTrue responses match but andFalse is
            // different
            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml(constructReflectedResponse(normalValue))
                            .whenParamValueIs(andTrueValue)
                            .thenReturnHtml(
                                    constructReflectedResponse(encodingFunction.apply(normalValue)))
                            .whenParamValueIs(andFalseValue)
                            .thenReturnHtml(
                                    constructReflectedResponse(encodingFunction.apply(normalValue))
                                            + "something different")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(actual.getAttack(), is(equalTo(andTrueValue)));
        }

        @Test
        void shouldAlertValueReflectedMultipleTimesAndWithDifferentEncodings() throws Exception {
            // Given
            String param = "param";
            String normalValue = "<a>%test"; // Includes characters that will be encoded
            String andTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            String andFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];

            // Set up the positive case where normal and andTrue responses match but andFalse is
            // different
            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml(constructReflectedResponse(normalValue))
                            .whenParamValueIs(andTrueValue)
                            .thenReturnHtml(
                                    constructReflectedResponse(escapeXml10(andTrueValue), 4))
                            .whenParamValueIs(andFalseValue)
                            .thenReturnHtml(
                                    constructReflectedResponse(
                                                    AbstractPlugin.getURLEncode(andFalseValue), 2)
                                            + "something different")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(actual.getAttack(), is(equalTo(andTrueValue)));
            assertNoParams(alertsRaised.get(0));
        }

        @Test
        void shouldNotAlertResponseIsSameForAllParameterOriginalParameterIsAlwaysInResponse()
                throws Exception {
            // Given
            String param = "param";
            String normalValue = "normal";
            String andTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_TRUE[0];
            String andFalseValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_AND_FALSE[0];
            String orTrueValue = normalValue + SqlInjectionScanRule.SQL_LOGIC_OR_TRUE[0];

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalValue)
                            .thenReturnHtml(constructReflectedResponse(normalValue) + normalValue)
                            .whenParamValueIs(andTrueValue)
                            .thenReturnHtml(constructReflectedResponse(andTrueValue) + normalValue)
                            .whenParamValueIs(andFalseValue)
                            .thenReturnHtml(constructReflectedResponse(andFalseValue) + normalValue)
                            .whenParamValueIs(orTrueValue)
                            .thenReturnHtml(constructReflectedResponse(orTrueValue) + normalValue)
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        private UrlParamValueHandler getLikeTestHandler(String normalValue) {
            // Set up the positive case where normal and andTrue responses match but andFalse is
            // different
            String param = "param";
            String andTrueValue = normalValue + SqlInjectionScanRule.SQL_LIKE;
            String andFalseValue = normalValue + SqlInjectionScanRule.SQL_LIKE_SAFE;
            return UrlParamValueHandler.builder()
                    .targetParam(param)
                    .whenParamValueIs(normalValue)
                    .thenReturnHtml(constructReflectedResponse(normalValue))
                    .whenParamValueIs(andTrueValue)
                    .thenReturnHtml(constructReflectedResponse(andTrueValue))
                    .whenParamValueIs(andFalseValue)
                    .thenReturnHtml(constructReflectedResponse("different from normal and ANDTrue"))
                    .build();
        }

        @Test
        void shouldNotAlertLikeAttacksStrengthMedium() throws Exception {
            // Given
            rule.setAttackStrength(AttackStrength.MEDIUM);
            String normalValue = "payload";
            nano.addHandler(getLikeTestHandler(normalValue));
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @Test
        void shouldAlertLikeAttacksStrengthHigh() throws Exception {
            // Given
            rule.setAttackStrength(AttackStrength.HIGH);
            String param = "param";
            String normalValue = "payload";

            nano.addHandler(getLikeTestHandler(normalValue));
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(
                    actual.getAttack(), is(equalTo(normalValue + SqlInjectionScanRule.SQL_LIKE)));
        }

        /** Build a short response that contains the payload reflected in some text */
        private String constructReflectedResponse(String payload) {
            return constructReflectedResponse(payload, 1);
        }

        private String constructReflectedResponse(String payload, int reflectionCount) {
            return "foo " + StringUtils.repeat(payload, reflectionCount) + " foo ";
        }

        @Test
        void shouldAlertByBodyComparisonIgnoringXmlEscapedPayload() throws Exception {
            // Given
            String param = "topic";
            String normalPayload = "cats";
            String attackPayload = "cats' AND '1'='1' -- ";
            String verificationPayload = "cats' AND '1'='2' -- ";
            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(normalPayload)
                            .thenReturnHtml(normalPayload + ": A")
                            .whenParamValueIs(attackPayload)
                            .thenReturnHtml(escapeXml10(attackPayload + ": A"))
                            .whenParamValueIs(verificationPayload)
                            .thenReturnHtml(escapeXml10(verificationPayload + ": "))
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?topic=" + normalPayload), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            Alert actual = alertsRaised.get(0);
            assertThat(actual.getParam(), is(equalTo(param)));
            assertThat(actual.getAttack(), is(equalTo(attackPayload)));
            assertNoParams(alertsRaised.get(0));
        }

        // False positive case - https://github.com/zaproxy/zaproxy/issues/8651
        @Test
        void shouldNotAlertIfNormalAndModified301RedirectToDifferentLocations() throws Exception {
            // Given
            String param = "test";
            String normalPayload = "1";
            String attackPayload = "2/2";
            String verificationPayload = "4/2";
            Map<String, Supplier<Response>> paramValueToResponseMap = new HashMap<>();
            paramValueToResponseMap.put(
                    normalPayload,
                    () -> {
                        final Response response =
                                newFixedLengthResponse(
                                        Status.REDIRECT, NanoHTTPD.MIME_HTML, "normal");
                        response.addHeader(HttpHeader.LOCATION, "https://test.com/location_one");
                        return response;
                    });
            paramValueToResponseMap.put(
                    attackPayload,
                    () -> {
                        final Response response =
                                newFixedLengthResponse(
                                        Status.REDIRECT, NanoHTTPD.MIME_HTML, "normal");
                        response.addHeader(HttpHeader.LOCATION, "https://test.com/location_two");
                        return response;
                    });
            paramValueToResponseMap.put(
                    verificationPayload,
                    () -> newFixedLengthResponse(Status.OK, NanoHTTPD.MIME_HTML, "text"));
            ControlledStatusCodeHandler handler =
                    new ControlledStatusCodeHandler(param, paramValueToResponseMap);
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?" + param + "=" + normalPayload), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @Test
        void shouldNotFailIfNormalAndModified301RedirectWithNoLocationHeaders() throws Exception {
            // Given
            String param = "test";
            String normalPayload = "1";
            String attackPayload = "2/2";
            String verificationPayload = "4/2";
            Map<String, Supplier<Response>> paramValueToResponseMap = new HashMap<>();
            paramValueToResponseMap.put(
                    normalPayload,
                    () -> {
                        return newFixedLengthResponse(
                                Status.REDIRECT, NanoHTTPD.MIME_HTML, "normal");
                    });
            paramValueToResponseMap.put(
                    attackPayload,
                    () -> {
                        return newFixedLengthResponse(
                                Status.REDIRECT, NanoHTTPD.MIME_HTML, "normal");
                    });
            paramValueToResponseMap.put(
                    verificationPayload,
                    () -> newFixedLengthResponse(Status.OK, NanoHTTPD.MIME_HTML, "text"));
            ControlledStatusCodeHandler handler =
                    new ControlledStatusCodeHandler(param, paramValueToResponseMap);
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?" + param + "=" + normalPayload), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
        }
    }

    @Nested
    class ErrorBasedSqlInjection {

        static List<String> allExceptGenericSqlErrors() {
            return ALL_EXCEPT_GENERIC_SQL_ERRORS;
        }

        static List<String> allSqlErrors() {
            return Stream.concat(
                            ALL_EXCEPT_GENERIC_SQL_ERRORS.stream(), GENERIC_SQL_ERRORS.stream())
                    .toList();
        }

        @ParameterizedTest
        @MethodSource("allExceptGenericSqlErrors")
        void shouldAlertEmptyPrefixMediumThreshold(String error) throws Exception {
            // Given
            String param = "param";
            String normalValue = "test";
            String emptyPrefixErrorValue = SqlInjectionScanRule.SQL_SINGLE_QUOTE;

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(emptyPrefixErrorValue)
                            .thenReturnHtml(error)
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            assertThat(alertsRaised.get(0).getEvidence(), equalTo(error));
            assertNoParams(alertsRaised.get(0));
        }

        @ParameterizedTest
        @MethodSource("allExceptGenericSqlErrors")
        void shouldAlertOriginalParamPrefixMediumThreshold(String error) throws Exception {
            // Given
            String param = "param";
            String normalValue = "test";
            String originalParamErrorValue = normalValue + SqlInjectionScanRule.SQL_SINGLE_QUOTE;

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(originalParamErrorValue)
                            .thenReturnHtml(error)
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            assertThat(alertsRaised.get(0).getEvidence(), equalTo(error));
            assertNoParams(alertsRaised.get(0));
        }

        @ParameterizedTest
        @MethodSource("allSqlErrors")
        void shouldAlertEmptyPrefixLowThreshold(String error) throws Exception {
            // Given
            String param = "param";
            String normalValue = "test";
            String emptyPrefixErrorValue = SqlInjectionScanRule.SQL_SINGLE_QUOTE;

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(emptyPrefixErrorValue)
                            .thenReturnHtml(error)
                            .build();
            nano.addHandler(handler);
            rule.setAlertThreshold(AlertThreshold.LOW);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            assertThat(alertsRaised.get(0).getEvidence(), equalTo(error));
            assertNoParams(alertsRaised.get(0));
        }

        @ParameterizedTest
        @MethodSource("allSqlErrors")
        void shouldAlertOriginalParamPrefixLowThreshold(String error) throws Exception {
            // Given
            String param = "param";
            String normalValue = "test";
            String originalParamErrorValue = normalValue + SqlInjectionScanRule.SQL_SINGLE_QUOTE;

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(originalParamErrorValue)
                            .thenReturnHtml(error)
                            .build();
            nano.addHandler(handler);
            rule.setAlertThreshold(AlertThreshold.LOW);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            assertThat(alertsRaised.get(0).getEvidence(), equalTo(error));
            assertNoParams(alertsRaised.get(0));
        }

        @Test
        void shouldNotAlertNonSqlMessage() throws Exception {
            // Given
            String param = "param";
            String normalValue = "test";
            String originalParamErrorValue = normalValue + SqlInjectionScanRule.SQL_SINGLE_QUOTE;

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(originalParamErrorValue)
                            .thenReturnHtml("Not a SQL error message")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @Test
        void shouldAlertGenericRdbmsErrorOnLowThreshold() throws Exception {
            // Given
            rule.setAlertThreshold(AlertThreshold.LOW);
            String param = "param";
            String normalValue = "test";
            String originalParamErrorValue = normalValue + SqlInjectionScanRule.SQL_SINGLE_QUOTE;

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(originalParamErrorValue)
                            .thenReturnHtml("java.sql.SQLException")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            assertNoParams(alertsRaised.get(0));
        }
    }

    @Nested
    class UnionBasedSqlInjection {

        private UrlParamValueHandler serverWithRdbmsError() {
            String param = "param";
            String normalValue = "test";
            String unionValueString =
                    normalValue
                            + SqlInjectionScanRule.SQL_UNION_SELECT
                            + SqlInjectionScanRule.SQL_ONE_LINE_COMMENT;

            return UrlParamValueHandler.builder()
                    .targetParam(param)
                    .whenParamValueIs(param)
                    .thenReturnHtml(normalValue)
                    .whenParamValueIs(unionValueString)
                    .thenReturnHtml("You have an error in your SQL syntax")
                    .build();
        }

        @Test
        void shouldAlertRdbmsErrorMessage() throws Exception {
            // Given
            nano.addHandler(serverWithRdbmsError());
            rule.init(getHttpMessage("/?param=test"), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
        }

        @Test
        void shouldNotRunStrengthLow() throws Exception {
            // Given
            nano.addHandler(serverWithRdbmsError());
            rule.setAttackStrength(AttackStrength.LOW);
            rule.init(getHttpMessage("/?param=test"), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @Test
        void shouldNotAlertNonErrorMessageResponse() throws Exception {
            // Given
            String param = "param";
            String normalValue = "test";
            String unionValueString =
                    normalValue
                            + SqlInjectionScanRule.SQL_UNION_SELECT
                            + SqlInjectionScanRule.SQL_ONE_LINE_COMMENT;

            UrlParamValueHandler handler =
                    UrlParamValueHandler.builder()
                            .targetParam(param)
                            .whenParamValueIs(param)
                            .thenReturnHtml(normalValue)
                            .whenParamValueIs(unionValueString)
                            .thenReturnHtml("This is not a sql error message")
                            .build();
            nano.addHandler(handler);
            rule.init(getHttpMessage("/?param=" + normalValue), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }
    }

    @Nested
    class FiveHundredErrors {

        private Response error500Response() {
            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.INTERNAL_ERROR,
                    NanoHTTPD.MIME_HTML,
                    "500 error handling request");
        }

        @Test
        void shouldAlertIf500OnSingleQuote() throws Exception {
            // Given
            String param = "id";

            nano.addHandler(
                    new NanoServerHandler("/") {
                        @Override
                        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                            String value = getFirstParamValue(session, param);
                            if (StringUtils.countMatches(value, "'") == 1) {
                                return error500Response();
                            }
                            String response = "<html><body></body></html>";
                            return newFixedLengthResponse(response);
                        }
                    });

            rule.init(getHttpMessage("/?" + param + "=test"), parent);
            // When
            rule.scan();
            // Then
            assertThat(httpMessagesSent, hasSize(equalTo(expectedRequestsForSingleQuote500())));
            assertThat(alertsRaised, hasSize(1));
            assertThat(
                    alertsRaised.get(0).getEvidence(),
                    is(equalTo("HTTP/1.1 500 Internal Server Error")));
            assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
            assertThat(alertsRaised.get(0).getAttack(), is(equalTo("'")));
            assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
            assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
            assertNoParams(alertsRaised.get(0));
        }

        @Test
        void shouldNotAlertIfAlways500() throws Exception {
            // Given
            String param = "id";

            nano.addHandler(
                    new NanoServerHandler("/") {
                        @Override
                        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                            return error500Response();
                        }
                    });

            HttpMessage msg = getHttpMessage("/?" + param + "=test");
            msg.getResponseHeader().setStatusCode(500);
            msg.getResponseHeader().setReasonPhrase("Internal Server Error");

            rule.init(msg, parent);
            // When
            rule.scan();
            // Then
            assertThat(alertsRaised, hasSize(0));
        }

        @Test
        void shouldNotAlertIfInvalidValuesResultIn500() throws Exception {
            // Given
            String param = "id";

            nano.addHandler(
                    new NanoServerHandler("/") {
                        @Override
                        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                            String value = getFirstParamValue(session, param);
                            if ("test".equals(value)) {
                                return newFixedLengthResponse("<html><body></body></html>");
                            }
                            return error500Response();
                        }
                    });

            HttpMessage msg = getHttpMessage("/?" + param + "=test");

            rule.init(msg, parent);
            // When
            rule.scan();
            // Then
            assertThat(alertsRaised, hasSize(0));
        }
    }

    /**
     * WAVSEP-inspired login bypass scenarios (Case01: injection in a login page with different 200
     * responses): the page only logs in when the injected value contains a quote together with an
     * OR based tautology, otherwise it consistently reports the failed login.
     */
    @Nested
    class LoginBypass {

        private static final String SUCCESS_BODY = "login success";
        private static final String FAILURE_BODY = "login failed";

        private UrlParamValueHandler orTautologyLoginPage() {
            return UrlParamValueHandler.builder()
                    .targetParam("username")
                    .when(param("username").matches(v -> v.contains("'") && v.contains("OR")))
                    .thenReturnHtml(SUCCESS_BODY)
                    .fallbackHtmlResponse(FAILURE_BODY)
                    .build();
        }

        @Test
        void shouldAlertLoginBypassWithDifferent200Responses() throws Exception {
            // Given
            nano.addHandler(orTautologyLoginPage());
            rule.init(getHttpMessage("/?username=admin"), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            assertThat(alertsRaised.get(0).getParam(), is(equalTo("username")));
        }

        @Test
        void shouldNotAlertLoginBypassWhenResponsesAreIdentical() throws Exception {
            // Given
            nano.addHandler(
                    UrlParamValueHandler.builder()
                            .targetParam("username")
                            .fallbackHtmlResponse(FAILURE_BODY)
                            .build());
            rule.init(getHttpMessage("/?username=admin"), parent);

            // When
            rule.scan();

            // Then
            assertThat(httpMessagesSent, hasSize(greaterThan(1)));
            assertThat(alertsRaised, hasSize(0));
        }
    }

    /**
     * Scenarios modelled on OWASP Juice Shop (Express + Sequelize + SQLite): {@code
     * routes/search.ts} concatenates the {@code q} value into two {@code LIKE} clauses and {@code
     * routes/login.ts} concatenates the {@code email} value into the {@code Users} lookup, both
     * mounted under {@code /rest}. The image runs the {@code errorhandler} middleware in
     * development mode, which is why the SQLite message is part of the response body, and {@code
     * server.ts} enables {@code bodyParser.urlencoded}, so a form-encoded POST reaches the same
     * query as the JSON body the Angular front-end sends.
     */
    @Nested
    class JuiceShopSqlInjection {

        private static final String SEARCH_PATH = "/rest/products/search";
        private static final String LOGIN_PATH = "/rest/user/login";

        private static final String PRODUCTS_JSON =
                "[{\"id\":1,\"name\":\"Apple Juice (1000ml)\",\"description\":\"The all-time"
                        + " classic.\",\"price\":1.99,\"deluxePrice\":0.99}]";

        /**
         * What Sequelize surfaces for a quote in {@code q}: the value is spliced into both {@code
         * LIKE} patterns, so the quote ends the second one early and sqlite3 rejects the statement.
         */
        private static final String SQLITE_ERROR_BODY =
                "<!DOCTYPE html><html><head><title>Error</title></head><body>"
                        + "<h1>500 Internal Server Error</h1><h2>SequelizeDatabaseError:"
                        + " SQLITE_ERROR: near &quot;&#39;%&#39;&quot;: syntax error</h2>"
                        + "<p>SELECT * FROM Products WHERE ((name LIKE &#39;%apple&#39;%&#39; OR"
                        + " description LIKE &#39;%apple&#39;%&#39;) AND deletedAt IS NULL) ORDER BY"
                        + " name</p></body></html>";

        /** {@code res.status(401).send(res.__('Invalid email or password.'))}. */
        private static final String LOGIN_FAILED_BODY = "Invalid email or password.";

        /** {@code res.json({ authentication: { token, bid, umail } })}. */
        private static final String LOGIN_SUCCESS_BODY =
                "{\"authentication\":{\"token\":\"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig\","
                        + "\"bid\":1,\"umail\":\"admin@juice-sh.op\"}}";

        @Test
        void shouldAlertSqliteErrorOnProductSearch() throws Exception {
            // Given: a quote in -q- leaves the second LIKE clause open, so the query fails.
            nano.addHandler(
                    UrlParamValueHandler.builder()
                            .targetPath(SEARCH_PATH)
                            .targetParam("q")
                            .errorOracle(500, SQLITE_ERROR_BODY)
                            .fallbackHtmlResponse(PRODUCTS_JSON)
                            .build());
            rule.init(getHttpMessage(SEARCH_PATH + "?q=apple"), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(1));
            assertThat(alertsRaised.get(0).getParam(), is(equalTo("q")));
        }

        @Test
        void shouldAlertLoginBypassOnAdminLogin() throws Exception {
            // Given: only the email is spliced in as-is (the password is hashed first), so a
            // tautology in the email logs the first user in -- by returning a session rather than
            // the "Invalid email or password." message.
            nano.addHandler(
                    UrlParamValueHandler.builder()
                            .targetPath(LOGIN_PATH)
                            .targetParam("email")
                            .when(
                                    formParam("email")
                                            .matches(
                                                    value ->
                                                            value.contains("'")
                                                                    && SQL_OR_OPERATOR
                                                                            .matcher(value)
                                                                            .find()))
                            .thenReturnJson(LOGIN_SUCCESS_BODY)
                            .when(formParam("email"))
                            .thenReturn(401, LOGIN_FAILED_BODY)
                            .build());
            rule.init(
                    formPost(
                            LOGIN_PATH,
                            LOGIN_FAILED_BODY,
                            "email=admin%40juice-sh.op&password=admin123"),
                    parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(greaterThan(0)));
            assertThat(alertsRaised.get(0).getParam(), is(equalTo("email")));
        }
    }

    /**
     * Scenarios modelled on OWASP Mutillidae II (PHP + MySQL): {@code SQLQueryHandler} concatenates
     * the request values into the query and {@code MySQLHandler} throws on {@code mysqli_error},
     * which {@code CustomErrorHandler::FormatError} then prints into the page together with the
     * query -- so the quote alone leaks the error, with no tautology involved. {@code
     * includes/process-login-attempt.php} answers a successful login with a 302 to the home page.
     */
    @Nested
    class MutillidaeSqlInjection {

        private static final String INDEX_PATH = "/index.php";
        private static final String USER_INFO_QUERY =
                "?page=user-info.php&username=admin&password=adminPass";

        private static final String NO_RECORDS_BODY =
                "<div id=\"id-query-results\"><p>Results for the account information selected. 0"
                        + " records found.</p></div>";

        /** What the same page shows for an account that does exist, i.e. the original value. */
        private static final String ACCOUNT_BODY =
                "<div id=\"id-query-results\"><p>Results for the account information selected. 1"
                        + " record found.</p><table id=\"id-accounts\"><tr><td>admin</td>"
                        + "<td>adminPass</td><td>Administrator</td></tr></table></div>";

        /** The page {@code login.php} renders again when the credentials are rejected. */
        private static final String LOGIN_FAILED_BODY =
                "<form action=\"index.php?page=login.php\" method=\"post\">"
                        + "<p>Username or password incorrect</p>"
                        + "<input type=\"text\" name=\"username\">"
                        + "<input type=\"password\" name=\"password\">"
                        + "<a href=\"index.php?page=register.php\">Register</a></form>";

        /**
         * The header menu ({@code includes/header.php}) once the session is logged in: the
         * "Login/Register" link of the login page has become a "Logout" one.
         */
        private static final String LOGGED_IN_BODY =
                "<table class=\"header-menu-table\"><tr>"
                        + "<td><a href=\"index.php?page=home.php"
                        + "&popUpNotificationCode=HPH0\">Home</a></td>"
                        + "<td>|</td><td><a href=\"index.php?do=logout\">Logout</a></td>"
                        + "</tr></table>";

        private static String queryWith(String username, String password) {
            return "SELECT * FROM accounts WHERE username=&#39;"
                    + username
                    + "&#39; AND password=&#39;"
                    + password
                    + "&#39;";
        }

        private static String errorBody(String query, String error) {
            return "<div class=\"error-message\"><p>Error executing query: "
                    + query
                    + "</p><p>Error: "
                    + error
                    + "</p></div>";
        }

        @Test
        void shouldAlertMysqlErrorOnUserInfoLookup() throws Exception {
            // Given: neither credential is escaped before it reaches the WHERE clause, so a quote
            // in either one breaks the query and MySQL's message ends up in the page.
            String error =
                    "You have an error in your SQL syntax; check the manual that corresponds to"
                            + " your MySQL server version for the right syntax to use near"
                            + " &#39;&#39;admin&#39;&#39; at line 1";
            nano.addHandler(
                    UrlParamValueHandler.builder()
                            .targetPath(INDEX_PATH)
                            .targetParam("username")
                            .when(param("username").is("admin"))
                            .thenReturn(200, ACCOUNT_BODY)
                            .when(param("username").matches(value -> value.contains("'")))
                            .thenReturn(200, errorBody(queryWith("admin'", "adminPass"), error))
                            .when(param("password").matches(value -> value.contains("'")))
                            .thenReturn(200, errorBody(queryWith("admin", "adminPass'"), error))
                            .fallbackHtmlResponse(NO_RECORDS_BODY)
                            .build());
            rule.init(getHttpMessage(INDEX_PATH + USER_INFO_QUERY), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(greaterThan(0)));
            assertThat(
                    alertsRaised.stream().map(Alert::getParam).toList(),
                    Matchers.hasItem("username"));
        }

        @Test
        void shouldAlertMysqlUnionColumnCountOnUserInfoLookup() throws Exception {
            // Given: the UNION variant of the same concatenation -- MySQL rejects it because the
            // SELECT the payload injects has a different number of columns.
            nano.addHandler(
                    UrlParamValueHandler.builder()
                            .targetPath(INDEX_PATH)
                            .targetParam("username")
                            .when(param("username").is("admin"))
                            .thenReturn(200, ACCOUNT_BODY)
                            .when(
                                    param("username")
                                            .matches(
                                                    value ->
                                                            value.toLowerCase(Locale.ROOT)
                                                                    .contains("union")))
                            .thenReturn(
                                    200,
                                    errorBody(
                                            queryWith("admin' UNION SELECT 1 -- ", "adminPass"),
                                            "The used SELECT statements have a different number"
                                                    + " of columns"))
                            .fallbackHtmlResponse(NO_RECORDS_BODY)
                            .build());
            rule.init(getHttpMessage(INDEX_PATH + USER_INFO_QUERY), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(greaterThan(0)));
            assertThat(
                    alertsRaised.stream().map(Alert::getParam).toList(),
                    Matchers.hasItem("username"));
        }

        @Test
        void shouldAlertWhenSuccessfulLoginRedirects() throws Exception {
            // Given: the login attempt under test gets the wrong password -- all a scanner has
            // unless it was handed real credentials -- so only a tautology in the username gets
            // in, and a successful login is a 302 to index.php?popUpNotificationCode=AU1. The scan
            // follows that redirect, so what the rule gets to judge on is the landing page, whose
            // menu offers a logged-in user "Logout" where the login form offered to log in.
            nano.addHandler(
                    UrlParamValueHandler.builder()
                            .targetPath(INDEX_PATH)
                            .targetParam("username")
                            .when(param("page").is("home.php"))
                            .thenReturn(200, LOGGED_IN_BODY)
                            .when(
                                    formParam("username")
                                            .matches(
                                                    value ->
                                                            value.contains("'")
                                                                    && SQL_OR_OPERATOR
                                                                            .matcher(value)
                                                                            .find()))
                            .withStatus(302)
                            .withHeader(
                                    HttpHeader.LOCATION,
                                    "/index.php?popUpNotificationCode=AU1&page=home.php")
                            .thenReturn("")
                            .fallbackHtmlResponse(LOGIN_FAILED_BODY)
                            .build());
            rule.init(
                    formPost(
                            INDEX_PATH + "?page=login.php",
                            LOGIN_FAILED_BODY,
                            "username=admin&password=wrongPassword"),
                    parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(greaterThan(0)));
            assertThat(
                    alertsRaised.stream().map(Alert::getParam).toList(),
                    Matchers.hasItem("username"));
        }

        @Test
        void shouldNotAlertWhenCredentialsAreEscaped() throws Exception {
            // Given: the same page with the values escaped before they are concatenated, so every
            // request gets the very same "0 records found" page -- no error, no difference.
            nano.addHandler(
                    UrlParamValueHandler.builder()
                            .targetPath(INDEX_PATH)
                            .targetParam("username")
                            .fallbackHtmlResponse(NO_RECORDS_BODY)
                            .build());
            rule.init(getHttpMessage(INDEX_PATH + USER_INFO_QUERY), parent);

            // When
            rule.scan();

            // Then
            assertThat(alertsRaised, hasSize(0));
        }
    }

    /**
     * Creates a POST request with an {@code application/x-www-form-urlencoded} body, as the login
     * forms of the applications the scenarios above are modelled on send it, together with the
     * response that request gets ({@code responseBody}) -- which is what a scan starting from a
     * captured login request has as its baseline.
     */
    private HttpMessage formPost(String path, String responseBody, String body) throws Exception {
        HttpMessage message = getHttpMessage("POST", path, responseBody);
        message.getRequestHeader()
                .setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.FORM_URLENCODED_CONTENT_TYPE);
        message.setRequestBody(body);
        return message;
    }

    private static class ExpressionBasedHandler extends NanoServerHandler {

        public enum Expression {
            SUM("1", "3-2", "4-2"),
            MULT("1", "2/2", "4/2");

            private final String value;
            private final String baseExpression;
            private final String confirmationExpression;

            Expression(String value, String expression, String confirmationExpression) {
                this.value = value;
                this.baseExpression = expression;
                this.confirmationExpression = confirmationExpression;
            }
        }

        private final String param;
        private final Expression expression;
        private final boolean confirmationFails;
        private String contentAddition = "";

        public ExpressionBasedHandler(String path, String param, Expression expression) {
            this(path, param, expression, false);
        }

        public ExpressionBasedHandler(
                String path, String param, Expression expression, boolean confirmationFails) {
            super(path);

            this.param = param;
            this.expression = expression;
            this.confirmationFails = confirmationFails;
        }

        public ExpressionBasedHandler(
                String parth,
                String param,
                Expression expression,
                boolean confirmationFails,
                String contentAddition) {
            this(parth, param, expression, confirmationFails);
            this.contentAddition = contentAddition;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            return newFixedLengthResponse(
                    Response.Status.OK, NanoHTTPD.MIME_HTML, getContent(value));
        }

        /**
         * A page that evaluates the expressions answers with the content of the evaluated value, so
         * the original value and the equivalent expression match while the confirming expression
         * resolves to a different value and answers different content. With {@code
         * confirmationFails} the confirming expression resolves to the same value as the original,
         * so nothing differs.
         *
         * <p>The difference is content rather than status code on purpose: a confirming expression
         * that differs from the original only by being answered with an error page is what
         * zaproxy/zaproxy#8651, #8653, #8652 and #9289 are about, and the rule no longer alerts on
         * that (see {@code ResponseComparator#isDifferenceExplainedByErrorStatus}).
         */
        protected String getContent(String value) {
            if (!confirmationFails && expression.confirmationExpression.equals(value)) {
                return "Some Other Content " + contentAddition;
            }
            return "Some Content " + contentAddition;
        }
    }

    /**
     * A test server that can respond with different status codes depending on the request payload
     */
    private static class ControlledStatusCodeHandler extends NanoServerHandler {
        private final String targetParam;
        // Supplier function because the test may send the same payload multiple times
        private final Map<String, Supplier<Response>> paramValueToResponseMap;
        private final Supplier<Response> fallbackResponse =
                () -> newFixedLengthResponse(Status.OK, NanoHTTPD.MIME_HTML, "");

        public ControlledStatusCodeHandler(
                String targetParam, Map<String, Supplier<Response>> paramValueToResponseMap) {
            super("/");
            this.targetParam = targetParam;
            this.paramValueToResponseMap = paramValueToResponseMap;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String actualParamValue = getFirstParamValue(session, targetParam);

            @SuppressWarnings("unchecked")
            Supplier<Response> responseFn =
                    (Supplier<Response>)
                            MapUtils.getObject(
                                    paramValueToResponseMap, actualParamValue, fallbackResponse);
            return responseFn.get();
        }
    }
}
