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
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionScenario.Outcome;

/**
 * Runs every corpus scenario once and prints the numbers rule 424242 is judged on: coverage, false
 * positives, false negatives, requests per parameter and alerts per parameter, at the default
 * {@code MEDIUM} attack strength.
 *
 * <p>The table is the artifact a change is compared against, kept one row per change in {@code
 * sqli-plan.md}.
 *
 * <p>It deliberately does not assert on the outcomes: whether a scenario alerts is already held by
 * {@link SqlInjectionScenarioCorpusTest}, one test per scenario, and asserting it again here would
 * only add a second failure for the same regression. What it does assert is that the corpus can
 * still produce meaningful numbers — at least one injectable and one non-injectable row, and no
 * duplicate ids — because without those, "coverage 100%" could just mean every row was deleted.
 *
 * <p>Attribution is per scenario, not per technique: alerts do not record which technique raised
 * them, so a per-technique number needs that recorded first.
 */
class SqlInjectionScenarioMetricsTest extends AbstractSqlInjectionModularScanRuleTest {

    /** What one scenario cost and produced, at the default attack strength. */
    private record ScenarioResult(
            String id, Outcome outcome, int alerts, int requests, String summary) {

        @Override
        public String toString() {
            return String.format(
                    "  %-30s %-10s alerts=%d requests=%-4d %s",
                    id, outcome, alerts, requests, summary);
        }
    }

    @Test
    void printsCorpusMetrics() throws Exception {
        List<SqlInjectionScenario> scenarios = SqlInjectionScenarioCorpus.scenarios();
        assertCorpusCanBeMeasured(scenarios);

        List<ScenarioResult> results = new ArrayList<>(scenarios.size());
        for (SqlInjectionScenario scenario : scenarios) {
            setUp();
            try {
                results.add(run(scenario));
            } finally {
                shutDownServer();
            }
        }

        printReport(results);
    }

    private ScenarioResult run(SqlInjectionScenario scenario) throws Exception {
        nano.addHandler(scenario.fixture().get());
        rule.init(getHttpMessage(scenario.requestTarget()), parent);

        rule.scan();

        return new ScenarioResult(
                scenario.id(),
                scenario.outcome(),
                alertsRaised.size(),
                httpMessagesSent.size(),
                alertSummary());
    }

    /** A short description of the alert, so a surprising row can be diagnosed from the table. */
    private String alertSummary() {
        if (alertsRaised.isEmpty()) {
            return "";
        }
        String evidence = alertsRaised.get(0).getEvidence();
        if (evidence == null || evidence.isEmpty()) {
            return "(no evidence)";
        }
        String flattened = evidence.replaceAll("\\s+", " ").trim();
        return flattened.length() > 60 ? flattened.substring(0, 57) + "..." : flattened;
    }

    /**
     * The corpus has to contain both kinds of row for the numbers to mean anything, and ids have to
     * be unique or a failing scenario cannot be identified from the table.
     */
    private static void assertCorpusCanBeMeasured(List<SqlInjectionScenario> scenarios) {
        assertThat(scenarios, hasSize(greaterThan(0)));
        long injectable = scenarios.stream().filter(s -> s.outcome() == Outcome.INJECTABLE).count();
        assertThat(injectable, greaterThanOrEqualTo(1L));
        assertThat(scenarios.size() - injectable, greaterThanOrEqualTo(1L));

        Set<String> ids = new HashSet<>();
        for (SqlInjectionScenario scenario : scenarios) {
            assertThat("duplicate corpus id: " + scenario.id(), ids.add(scenario.id()), is(true));
            assertThat(
                    "corpus row without a source: " + scenario.id(),
                    scenario.source().isEmpty(),
                    is(false));
        }
    }

    private static void printReport(List<ScenarioResult> results) {
        long injectable = count(results, Outcome.INJECTABLE);
        long truePositives = 0;
        long falsePositivesSafe = 0;
        long falsePositivesFpProne = 0;
        int totalRequests = 0;
        int totalAlerts = 0;
        int fewestRequests = Integer.MAX_VALUE;
        int mostRequests = 0;
        for (ScenarioResult result : results) {
            boolean alerted = result.alerts() > 0;
            if (alerted && result.outcome() == Outcome.INJECTABLE) {
                truePositives++;
            } else if (alerted && result.outcome() == Outcome.SAFE) {
                falsePositivesSafe++;
            } else if (alerted) {
                falsePositivesFpProne++;
            }
            totalRequests += result.requests();
            totalAlerts += result.alerts();
            fewestRequests = Math.min(fewestRequests, result.requests());
            mostRequests = Math.max(mostRequests, result.requests());
        }

        PrintStream out = System.out;
        out.println();
        out.println("=== SQL injection corpus metrics (rule 424242, MEDIUM strength) ===");
        out.printf(
                "scenarios: %d  injectable: %d  safe: %d  fp-prone: %d%n",
                results.size(),
                injectable,
                count(results, Outcome.SAFE),
                count(results, Outcome.FP_PRONE));
        out.printf(
                "coverage:         %d/%d (%.1f%%)%n",
                truePositives, injectable, percentage(truePositives, injectable));
        out.printf(
                "false positives:  %d  (safe: %d, fp-prone: %d)%n",
                falsePositivesSafe + falsePositivesFpProne,
                falsePositivesSafe,
                falsePositivesFpProne);
        out.printf("false negatives:  %d%n", injectable - truePositives);
        out.printf(
                "requests/param:   mean %.1f  min %d  max %d%n",
                average(totalRequests, results.size()), fewestRequests, mostRequests);
        out.printf("alerts/param:     mean %.2f%n", average(totalAlerts, results.size()));
        out.println("per scenario:");
        results.forEach(out::println);
        out.println("=== end corpus metrics ===");
        out.println();
    }

    private static long count(List<ScenarioResult> results, Outcome outcome) {
        return results.stream().filter(r -> r.outcome() == outcome).count();
    }

    private static double percentage(long part, long total) {
        return total == 0 ? 0 : (part * 100.0) / total;
    }

    private static double average(int total, int count) {
        return count == 0 ? 0 : (double) total / count;
    }
}
