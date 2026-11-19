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
package org.zaproxy.zap.extension.ascanrules.sqli.strategies;

import java.io.IOException;
import java.util.Locale;
import java.util.regex.Pattern;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.ascanrules.sqli.DetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.ScanContext;

/**
 * Detects a login form's SQL injection by anchoring the bypass to the username already in the
 * request, rather than to an {@code OR} tautology.
 *
 * <p>{@code <value>' -- } drops the password check but, unlike {@code ' OR '1'='1' -- }, only ever
 * reaches the row that already matches {@code <value>}: on a vulnerable {@code SELECT} it changes
 * which column is checked, never how many rows match, and on a vulnerable {@code UPDATE} or {@code
 * DELETE} it narrows the affected rows rather than hitting every one. The probe is verified with a
 * restrict-then-confirm pair ({@code <value>' AND '1'='2' -- } must fail), run only at HIGH/INSANE
 * strength, whose baseline looks like a login form, and only when nothing else has already found
 * the injection (the orchestrator runs this strategy last). Not restricted to POST: a login form
 * submitted over GET is bad practice but real, and the anchoring safety property above holds
 * regardless of HTTP method.
 *
 * <p>This is deliberately narrower than guessing a username: it reaches only the account already
 * being tested (for example the account the scan is authenticated as, or one seen during crawling),
 * so a target with no such username in scope is correctly left untested rather than probed with an
 * invented one.
 */
public class LoginBypassDetectionStrategy implements DetectionStrategy {

    /** Requests this technique can send: the bypass probe and its restrict-verify pair. */
    static final int REQUESTS = 2;

    /**
     * Login markers, matched on word boundaries so "author" and "compass" don't count as "auth",
     * and "passwd" style fields are still covered by the broader "pass".
     */
    private static final Pattern LOGIN_CONTEXT =
            wordBoundary("login", "password", "username", "user", "pass", "auth");

    /**
     * Markers of a logged-in response, matched on word boundaries. A marker is only treated as
     * evidence when it is absent from the baseline, so its presence on the login page itself (where
     * "home" and "authenticated" often already appear) can never be the reason for an alert.
     *
     * <p>Which marker an application uses is what a scanner cannot know up front -- sqlmap has to
     * be told with {@code --string} or {@code --code} -- so a JSON API's session counts here the
     * same way a page saying "welcome" does.
     */
    private static final Pattern SUCCESS_MARKERS =
            wordBoundary(
                    "welcome",
                    "hello",
                    "dashboard",
                    "home",
                    "authenticated",
                    "success",
                    // The menu a logged-in page offers where the login page offers to log in
                    // (Mutillidae II's includes/header.php swaps "Login/Register" for "Logout").
                    "logout",
                    // A JSON login API (e.g. Juice Shop's /rest/user/login) answers with a session
                    // instead of a greeting: {"authentication":{"token":"...","bid":1}}.
                    "authentication",
                    "token",
                    "jwt");

    private static Pattern wordBoundary(String... words) {
        StringBuilder sb = new StringBuilder();
        for (String word : words) {
            if (sb.length() > 0) {
                sb.append('|');
            }
            sb.append("\\b").append(Pattern.quote(word)).append("\\b");
        }
        return Pattern.compile(sb.toString(), Pattern.CASE_INSENSITIVE);
    }

    @Override
    public boolean detect(ScanContext context) throws IOException {
        AttackStrength strength = context.getAttackStrength();
        if ((strength != AttackStrength.HIGH && strength != AttackStrength.INSANE)
                || context.getRemainingBudget() < REQUESTS) {
            return false;
        }

        String originalValue = context.getOriginalValue();
        if (originalValue == null || originalValue.isEmpty()) {
            // Nothing to anchor the bypass to.
            return false;
        }

        HttpMessage baseline = context.getCachedBaseline();
        String baselineBody = baseline.getResponseBody().toString();
        // A body-less login (the common POST/redirect/GET flow: the submit handler itself
        // answers with a bare redirect and no content, and the real page only loads on the
        // follow-up GET) carries no keyword for the body check, so the request path is tried too
        // -- confirmed live against AltoroJ, whose doLogin answers every attempt, failed or not,
        // with an empty-bodied 302.
        if (!isLoginContext(baselineBody) && !pathLooksLikeLogin(baseline)) {
            return false;
        }

        String bypassValue = originalValue + "' -- ";
        HttpMessage bypassMsg = context.newMessage();
        context.setParam(bypassMsg, bypassValue);
        context.sendAndReceive(bypassMsg);

        // The baseline can only be judged by its body text here: comparing it against itself for
        // the redirect signal would be vacuous (nothing to differ from), so that half of
        // looksLoggedIn is skipped for it on purpose.
        if (!looksLoggedIn(bypassMsg, baseline) || hasSuccessIndicators(baselineBody)) {
            return false;
        }

        // Restrict-verify: the same username with a false condition must not also look logged in,
        // so the success above is the username row being matched regardless of password, not some
        // other reason the page always looks logged in for this value.
        String verifyValue = originalValue + "' AND '1'='2' -- ";
        HttpMessage verifyMsg = context.newMessage();
        context.setParam(verifyMsg, verifyValue);
        context.sendAndReceive(verifyMsg);
        if (looksLoggedIn(verifyMsg, baseline)) {
            return false;
        }

        context.newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setParam(context.getParamName())
                .setAttack(bypassValue)
                .setOtherInfo(
                        "Authentication bypassed for the existing value ["
                                + originalValue
                                + "] by appending ' -- , without widening which rows the query"
                                + " matches")
                .setMessage(bypassMsg)
                .raise();
        return true;
    }

    private static boolean isLoginContext(String text) {
        return text != null && LOGIN_CONTEXT.matcher(text).find();
    }

    /**
     * Whether the request's own path names a login action, such as {@code doLogin} or {@code
     * login.jsp}. A plain substring match, not {@link #LOGIN_CONTEXT}'s word-boundary one: a path
     * segment concatenates words with no separator ({@code doLogin} has no boundary between "do"
     * and "Login"), so the free-text pattern would never match it.
     */
    private static boolean pathLooksLikeLogin(HttpMessage message) {
        return message.getRequestHeader()
                .getURI()
                .toString()
                .toLowerCase(Locale.ROOT)
                .contains("login");
    }

    /**
     * Whether {@code message} looks like a successful login: its body carries one of the {@link
     * #SUCCESS_MARKERS}, or -- when the body is empty, the common POST/redirect/GET flow -- it
     * redirects somewhere that isn't the login page itself.
     *
     * <p>Confirmed live against AltoroJ: every failed attempt, including the restrict-verify probe,
     * answers with an empty-bodied 302 back to {@code login.jsp}; the one payload that actually
     * bypasses the check instead redirects to {@code bank/main.jsp} and sets an additional
     * application cookie. Comparing against {@code reference} (the baseline, for both probes) is
     * what keeps a page that always redirects to the same non-login location -- one with no
     * password check to bypass in the first place -- from reading as a success here: that shape
     * repeats for the baseline too, so it is not treated as evidence either.
     *
     * <p>Package-private rather than {@code private}: the redirect branch only matters when a
     * login redirect's target is out of the scan's scope, so the real sender never follows it and
     * this strategy sees the bare 3xx -- a condition the active-scan test harness cannot produce
     * (its {@code HostProcess} override always reports every target in scope), so that branch is
     * exercised directly here instead of through {@code rule.scan()}.
     *
     * @param message the probe response to judge
     * @param reference the baseline response, judged by the same rule for comparison
     * @return {@code true} if {@code message} looks logged in and {@code reference} does not
     */
    static boolean looksLoggedIn(HttpMessage message, HttpMessage reference) {
        if (hasSuccessIndicators(message.getResponseBody().toString())) {
            return true;
        }
        if (!message.getResponseBody().toString().isEmpty()) {
            return false;
        }
        return isRedirectAwayFromLogin(message) && !isRedirectAwayFromLogin(reference);
    }

    private static boolean isRedirectAwayFromLogin(HttpMessage message) {
        int status = message.getResponseHeader().getStatusCode();
        if (!HttpStatusCode.isRedirection(status)) {
            return false;
        }
        String location = message.getResponseHeader().getHeader(HttpHeader.LOCATION);
        return location != null && !isLoginContext(location);
    }

    private static boolean hasSuccessIndicators(String body) {
        return SUCCESS_MARKERS.matcher(body).find();
    }
}
