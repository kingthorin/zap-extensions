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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.parosproxy.paros.network.HttpMessage;

/**
 * The rule under test, with the request and near-miss counters the corpus metrics and the presence
 * prior tests report. Kept out of the production rule: nothing outside the tests reads them.
 *
 * <p>All counters cover the request last scanned, summed over every one of its parameters. The
 * baseline and control messages, fetched once per parameter, are not charged to a technique.
 */
public class MeteredSqlInjectionModularScanRule extends SqlInjectionModularScanRule {

    private final Map<String, Integer> techniqueRequests = new HashMap<>();
    private String currentTechnique = "";
    private int baselineMatches;
    private int suppressedDifferentials;

    @Override
    public void init() {
        super.init();
        techniqueRequests.clear();
        baselineMatches = 0;
        suppressedDifferentials = 0;
    }

    @Override
    public void setCurrentTechnique(String technique) {
        super.setCurrentTechnique(technique);
        currentTechnique = technique;
    }

    @Override
    public void sendAndReceive(HttpMessage message) throws IOException {
        super.sendAndReceive(message);
        techniqueRequests.merge(currentTechnique, 1, Integer::sum);
    }

    @Override
    public void recordBaselineMatch() {
        baselineMatches++;
    }

    @Override
    public void recordSuppressedDifferential() {
        suppressedDifferentials++;
    }

    /**
     * What each technique spent on the request scanned last, keyed by technique name.
     *
     * @return an unmodifiable map of technique name to the requests it sent
     */
    public Map<String, Integer> getTechniqueRequests() {
        return Map.copyOf(techniqueRequests);
    }

    /**
     * How many probes matched the baseline: the gate every differential technique passes before it
     * can alert. A non-injectable row with a non-zero count is a near miss.
     *
     * @return the number of baseline matches recorded
     */
    public int getBaselineMatchCount() {
        return baselineMatches;
    }

    /**
     * How many would-have-alerted differentials the error-status guard suppressed (rate limited,
     * WAF, timed out).
     *
     * @return the number of suppressed differentials recorded
     */
    public int getSuppressedDifferentialCount() {
        return suppressedDifferentials;
    }
}
