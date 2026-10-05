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
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;

import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionScenario.Outcome;

/**
 * Tests the presence prior: a technique that has found an injection is tried first next time, and
 * the per-technique spend is recorded so the reordering can be judged rather than assumed.
 *
 * <p>The prior lives in the scanner's knowledge base, which is write-once and has no removal, so
 * each test gets its own host process (the harness builds one per test) and never has to clear
 * anything.
 */
class SqlInjectionPresencePriorTest extends AbstractSqlInjectionModularScanRuleTest {

    /**
     * The point of the prior: the second time a request is scanned, the technique that found the
     * injection is tried first, so the same alert arrives in fewer requests.
     *
     * <p>Measured on the {@code UNION} row, which is the case the prior is for: {@code UNION} runs
     * fifth in the declared order, so a cold scan pays for the four techniques ahead of it first.
     */
    @Test
    void repeatScanSpendsFewerRequestsBecauseTheKnownTechniqueRunsFirst() throws Exception {
        SqlInjectionScenario scenario = scenario("royal-event-date-filter-canary");

        // Given
        nano.addHandler(scenario.fixture().get());
        rule.init(scenarioRequest(scenario), parent);
        rule.scan();

        // When
        assertThat(alertsRaised, hasSize(1));
        int firstScan = httpMessagesSent.size();

        rule.init(scenarioRequest(scenario), parent);
        rule.scan();

        // Then
        assertThat("the injection is still found on the second scan", alertsRaised, hasSize(2));
        int secondScan = httpMessagesSent.size() - firstScan;
        assertThat(
                "second scan sends "
                        + secondScan
                        + " requests against "
                        + firstScan
                        + " on the first",
                secondScan,
                lessThan(firstScan));
    }

    /**
     * The counter-example that matters most: the prior reorders, it never skips. A parameter that
     * only another technique can find must still be found while the prior points elsewhere.
     */
    @Test
    void presencePriorDoesNotHideAnInjectionFoundByAnotherTechnique() throws Exception {
        // Given a host where error-based probing has found an injection
        SqlInjectionScenario errorScenario = scenario("sqlite-error-in-500");
        nano.addHandler(errorScenario.fixture().get());
        rule.init(scenarioRequest(errorScenario), parent);
        rule.scan();

        assertThat(alertsRaised, hasSize(1));
        assertThat(
                "the first injection is found by the error technique: "
                        + rule.getTechniqueRequests(),
                rule.getTechniqueRequests().get("ERROR"),
                is(greaterThan(0)));

        // When a boolean-only injection on the same host is scanned, which the prior says to look
        // for
        // with error-based probing first
        SqlInjectionScenario booleanScenario = scenario("boolean-injected-id");
        nano.addHandler(booleanScenario.fixture().get());
        rule.init(scenarioRequest(booleanScenario), parent);
        rule.scan();

        // Then
        assertThat("the boolean injection is still found", alertsRaised, hasSize(2));
        // Error-based probing found nothing here and spent its whole budget, which it could only do
        // by running ahead of the boolean-based probing that did find the injection.
        assertThat(
                "error-based ran ahead of the technique that found it: "
                        + rule.getTechniqueRequests(),
                rule.getTechniqueRequests().get("ERROR"),
                is(greaterThan(0)));
        assertThat(
                "boolean-based still found it: " + rule.getTechniqueRequests(),
                rule.getTechniqueRequests().get("BOOLEAN"),
                is(greaterThan(0)));
    }

    /**
     * The per-technique spend has to account for every probe a scan sends, or the technique column
     * in the metrics table is measuring something other than what it claims.
     */
    @Test
    void perTechniqueRequestsCoverEveryProbeButNotTheBaselineAndControl() throws Exception {
        // Given
        SqlInjectionScenario scenario = scenario("boolean-injected-id");
        nano.addHandler(scenario.fixture().get());
        rule.init(scenarioRequest(scenario), parent);

        // When
        rule.scan();

        // Then
        Map<String, Integer> byTechnique = rule.getTechniqueRequests();
        int charged = byTechnique.values().stream().mapToInt(Integer::intValue).sum();
        assertThat(
                "each parameter's baseline and control are uncharged, every probe is charged: sent "
                        + httpMessagesSent.size()
                        + ", charged "
                        + charged,
                charged + 2,
                is(equalTo(httpMessagesSent.size())));
    }

    /**
     * A record written by another version of this rule is ignored rather than trusted: the
     * knowledge base cannot be purged, so the version stamp is the only way a future format can
     * retire what it wrote.
     */
    @ParameterizedTest
    @ValueSource(strings = {"", "v0", "v2", "true", "1"})
    void presenceRecordFromAnotherVersionIsIgnored(String record) {
        assertThat(SqlInjectionModularScanRule.isCurrentRecord(record), is(false));
    }

    @Test
    void presenceRecordOfThisVersionIsUsed() {
        assertThat(SqlInjectionModularScanRule.isCurrentRecord("v1"), is(true));
    }

    /** Every injectable row, with the technique that finds it, as a {@link MethodSource}. */
    static Stream<ExpectedDetection> injectableScenarios() {
        return Stream.of(
                new ExpectedDetection(scenario("sqlite-error-in-500"), "ERROR"),
                new ExpectedDetection(scenario("boolean-injected-id"), "BOOLEAN"),
                new ExpectedDetection(scenario("wordpress-tax-query-json"), "ERROR"),
                new ExpectedDetection(scenario("royal-event-date-filter-canary"), "UNION"));
    }

    /** One injectable corpus row and the technique the rule is expected to find it with. */
    record ExpectedDetection(SqlInjectionScenario scenario, String technique) {}

    /**
     * With no prior the techniques keep the order the static priors give them, and each injection
     * is still found -- the reordering may change which technique gets there first, not whether it
     * does.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("injectableScenarios")
    void coldScanFindsEachInjectionWithTheExpectedTechnique(ExpectedDetection expected)
            throws Exception {
        // Given
        assertThat(expected.scenario().outcome(), is(Outcome.INJECTABLE));
        nano.addHandler(expected.scenario().fixture().get());
        rule.init(scenarioRequest(expected.scenario()), parent);

        // When
        rule.scan();

        // Then
        assertThat(expected.scenario().id(), alertsRaised, hasSize(1));
        assertThat(
                expected.technique()
                        + " should have found the injection: "
                        + rule.getTechniqueRequests(),
                rule.getTechniqueRequests().containsKey(expected.technique()),
                is(true));
    }

    /**
     * Every injectable row is still found when its own prior is warm, so no coverage is traded
     * away.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("injectableScenarios")
    void everyInjectableRowAlertsAgainOnAWarmPrior(ExpectedDetection expected) throws Exception {
        // Given
        assertThat(expected.scenario().outcome(), is(Outcome.INJECTABLE));
        nano.addHandler(expected.scenario().fixture().get());

        // When
        rule.init(scenarioRequest(expected.scenario()), parent);
        rule.scan();
        rule.init(scenarioRequest(expected.scenario()), parent);
        rule.scan();

        // Then
        assertThat(expected.scenario().id(), alertsRaised, hasSize(2));
    }

    private static SqlInjectionScenario scenario(String id) {
        return SqlInjectionScenarioCorpus.scenarios().stream()
                .filter(candidate -> candidate.id().equals(id))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no corpus scenario with id " + id));
    }
}
