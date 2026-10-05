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
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionScenario.Outcome;

/**
 * Runs every corpus scenario once and prints the numbers rule 424242 is judged on: coverage, false
 * positives, false negatives, and the requests and alerts a row costs, at the default {@code
 * MEDIUM} attack strength. A row is one request with all of its parameters, so the request column
 * is per row, not per parameter: a three-parameter row scans three parameters and pays three times
 * the per-parameter ceiling.
 *
 * <p>The table is the artifact a change is compared against, kept one row per change in {@code
 * sqli-plan.md}.
 *
 * <p>Each row is scanned twice: once cold, which is what a user scanning a site for the first time
 * sees, and once more with the presence prior the first scan recorded. Both counts are reported,
 * because the prior can only show itself on the second one.
 *
 * <p>It deliberately does not assert on the outcomes: whether a scenario alerts is already held by
 * {@link SqlInjectionScenarioCorpusTest}, one test per scenario, and asserting it again here would
 * only add a second failure for the same regression. What it does assert is that the corpus can
 * still produce meaningful numbers — at least one injectable and one non-injectable row, and no
 * duplicate ids — because without those, "coverage 100%" could just mean every row was deleted.
 *
 * <p>Attribution is per technique as well as per scenario: the rule records what each technique
 * spent on the request it last scanned, so a row shows both the total and which techniques paid for
 * it. That is what makes a change to the order techniques run in measurable -- a reordering that
 * costs the same requests but finds the same thing is not a change anyone needs, and a reordering
 * that costs more to find the same thing is a regression.
 *
 * <p>The one outcome it does assert is not a scenario label but the prior's own contract: a row
 * scanned again with a warm presence prior must find exactly what the cold scan found. That holds
 * for every row, injectable or not, and it is the guard on the one thing technique reordering is
 * allowed to change -- the order, never what gets found.
 */
class SqlInjectionScenarioMetricsTest extends AbstractSqlInjectionModularScanRuleTest {

    /** What one scenario cost and produced, at the default attack strength. */
    private record ScenarioResult(
            String id,
            Outcome outcome,
            int alerts,
            int requests,
            int repeatRequests,
            String summary,
            Map<String, Integer> byTechnique) {

        @Override
        public String toString() {
            return String.format(
                    "  %-30s %-10s alerts=%d requests=%-4d repeat=%-4d %-40s %s",
                    id, outcome, alerts, requests, repeatRequests, summary, techniqueSpend());
        }

        /** The per-technique breakdown, in a stable order so two runs are comparable by eye. */
        private String techniqueSpend() {
            return byTechnique.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .map(entry -> entry.getKey() + "=" + entry.getValue())
                    .reduce((left, right) -> left + " " + right)
                    .orElse("");
        }
    }

    @Test
    void printsCorpusMetrics() throws Exception {
        List<SqlInjectionScenario> scenarios = SqlInjectionScenarioCorpus.scenarios();

        List<ScenarioResult> results = new ArrayList<>(scenarios.size());
        for (SqlInjectionScenario scenario : scenarios) {
            setUp();
            try {
                results.add(run(scenario));
            } finally {
                shutDownServer();
            }
        }

        assertCorpusCanBeMeasured(scenarios, results);
        printReport(results);
    }

    private ScenarioResult run(SqlInjectionScenario scenario) throws Exception {
        nano.addHandler(scenario.fixture().get());
        rule.init(scenarioRequest(scenario), parent);

        rule.scan();

        int requests = httpMessagesSent.size();
        int alerts = alertsRaised.size();
        String summary = alertSummary();
        Map<String, Integer> byTechnique = rule.getTechniqueRequests();

        // The same request scanned again, with whatever the first scan recorded now in the prior.
        // A cold scan cannot show what the prior is for -- it has no records to read -- so the
        // repeat column is the measurement of it, and it must find the same thing for less.
        rule.init(scenarioRequest(scenario), parent);
        rule.scan();
        int repeatRequests = httpMessagesSent.size() - requests;
        assertThat(
                scenario.id() + " must find exactly what the cold scan found, prior or not",
                alertsRaised.size() - alerts,
                is(alerts));

        return new ScenarioResult(
                scenario.id(),
                scenario.outcome(),
                alerts,
                requests,
                repeatRequests,
                summary,
                byTechnique);
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
     * The corpus has to contain both kinds of row for the numbers to mean anything, ids have to be
     * unique or a failing scenario cannot be identified from the table, and every row has to have
     * been scanned at all: a row that sent no requests is a fixture or a request that is wrong, and
     * reporting that as "no alerts" would hide it instead of failing.
     */
    private static void assertCorpusCanBeMeasured(
            List<SqlInjectionScenario> scenarios, List<ScenarioResult> results) {
        assertThat(scenarios, hasSize(greaterThan(0)));
        long injectable = scenarios.stream().filter(SqlInjectionScenario::expectsAlert).count();
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
        for (ScenarioResult result : results) {
            assertThat(
                    "corpus row that was never scanned: " + result.id(),
                    result.requests(),
                    greaterThan(0));
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
                "scenarios: %d  injectable: %d  safe: %d  fp-prone: %d  blind: %d%n",
                results.size(),
                injectable,
                count(results, Outcome.SAFE),
                count(results, Outcome.FP_PRONE),
                count(results, Outcome.BLIND));
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
                "known blind gaps: %d  (injectable, time-based only: no technique for it)%n",
                count(results, Outcome.BLIND));
        out.printf(
                "requests/row:     mean %.1f  min %d  max %d%n",
                average(totalRequests, results.size()), fewestRequests, mostRequests);
        out.printf(
                "repeat visits:    mean %.1f  (same request, prior warm; a warm prior must cost no more)%n",
                average(
                        results.stream().mapToInt(ScenarioResult::repeatRequests).sum(),
                        results.size()));
        out.printf("alerts/row:       mean %.2f%n", average(totalAlerts, results.size()));
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
