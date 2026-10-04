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

import java.util.function.Supplier;
import org.zaproxy.zap.testutils.NanoServerHandler;

/**
 * A labelled, runnable scenario: the unit the SQL injection corpus measures.
 *
 * <p>The corpus exists so that changes to rule 424242 can be judged on numbers rather than on
 * individual passing tests: how many injectable scenarios are detected (coverage), how many
 * non-injectable ones are not (false positives), how many injectable ones are missed (false
 * negatives), and how many requests each scenario costs. Each row carries the label that says which
 * of those it is, so a single parameterised test can assert the label and a single runner can
 * aggregate the counts.
 *
 * <p>These rows overlap deliberately with the named tests in the shared test base and the strategy
 * unit tests: those pin individual behaviours, these are the app-shaped rows the metrics are
 * computed from.
 *
 * @param id stable identifier, used in test names and the metrics table
 * @param outcome what the rule is expected to do, and why
 * @param source where the scenario comes from, e.g. {@code zaproxy/zaproxy#8651}
 * @param requestTarget the path and query the rule is initialised with
 * @param requestBody an {@code application/x-www-form-urlencoded} body, empty for a GET request
 * @param fixture the server fixture answering the requests of the scenario
 */
public record SqlInjectionScenario(
        String id,
        Outcome outcome,
        String source,
        String requestTarget,
        String requestBody,
        Supplier<NanoServerHandler> fixture) {

    /** What the rule is expected to do with a scenario, and why it is in the corpus. */
    public enum Outcome {
        /**
         * The application really is injectable, so the rule must alert. Counts towards coverage.
         */
        INJECTABLE,
        /**
         * Not injectable, and nothing about it should look like it: the rule must not alert. A
         * false positive here is a plain false positive.
         */
        SAFE,
        /**
         * Not injectable, but shaped so that a naive difference check alerts: a rate limiter, a
         * WAF, an error page, an int-cast id. The rule must not alert, and a false positive here is
         * the regression a reported ticket describes.
         */
        FP_PRONE,
        /**
         * Injectable, but only observable through a channel the rule does not have — a real blind,
         * time-based injection, where the response is the same however the query resolves. The rule
         * must not alert, and this is reported separately rather than as a false negative, because
         * calling it one would hide that it is a known and accepted limit: rule 424242 has no
         * time-based technique, for the same reason the time-based half of zaproxy/zaproxy#8525
         * does not apply to it.
         */
        BLIND
    }

    /** Whether the rule is expected to alert on a scenario with this outcome. */
    public boolean expectsAlert() {
        return outcome == Outcome.INJECTABLE;
    }

    @Override
    public String toString() {
        return id + " [" + outcome + ", " + source + "]";
    }
}
