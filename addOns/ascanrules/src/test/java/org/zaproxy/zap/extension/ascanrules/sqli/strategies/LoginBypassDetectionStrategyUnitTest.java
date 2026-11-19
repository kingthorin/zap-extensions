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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.zaproxy.zap.testutils.RequestCondition.formParam;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascanrules.sqli.AbstractSqlInjectionModularScanRuleTest;
import org.zaproxy.zap.testutils.UrlParamValueHandler;

/**
 * Unit test for {@link LoginBypassDetectionStrategy}, modelled on AltoroJ's {@code DBUtil
 * .isValidUser}: {@code SELECT COUNT(*) FROM PEOPLE WHERE USER_ID = '<uid>' AND PASSWORD = '<pw>'},
 * where appending {@code ' -- } to an existing username drops the password check and logs the
 * request in as that user, without any {@code OR}. Confirmed live against a local AltoroJ
 * container: {@code uid=jsmith' -- } logs in as {@code jsmith} with any password.
 */
class LoginBypassDetectionStrategyUnitTest extends AbstractSqlInjectionModularScanRuleTest {

    private static final String LOGIN_FAILED = "<html><body>login failed</body></html>";
    private static final String LOGIN_SUCCESS = "<html><body>welcome, logged in</body></html>";

    /**
     * A login whose check the anchored bypass (but not a plain quote, nor the old {@code OR}
     * tautology) defeats: only the exact {@code "<username>' -- "} shape -- everything after {@code
     * -- } is a SQL comment -- drops the password check.
     */
    private static UrlParamValueHandler.Builder altoroStyleLoginHandler(
            String path, String validUsername) {
        return UrlParamValueHandler.builder()
                .targetPath(path)
                .targetParam("uid")
                .whenParamValueIs(validUsername + "' -- ")
                .thenReturnHtml(LOGIN_SUCCESS)
                .fallbackHtmlResponse(LOGIN_FAILED);
    }

    private void postLogin(String path, String uid) throws Exception {
        rule.setAttackStrength(AttackStrength.HIGH);
        rule.init(formPost(path, "uid=" + uid), parent);
        rule.scan();
    }

    /** A POST whose body carries the parameters, the shape a real login form submits. */
    private HttpMessage formPost(String path, String body) throws Exception {
        HttpMessage message = getHttpMessage("POST", path, "");
        message.getRequestHeader()
                .setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.FORM_URLENCODED_CONTENT_TYPE);
        message.setRequestBody(body);
        return message;
    }

    @Test
    void shouldAlertWhenAnchoredBypassLogsInAsExistingUser() throws Exception {
        // Given
        String path = "/altoro/login/";
        nano.addHandler(altoroStyleLoginHandler(path, "jsmith").build());

        // When
        postLogin(path, "jsmith");

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("uid")));
        assertThat(alertsRaised.get(0).getAttack(), is(equalTo("jsmith' -- ")));
    }

    /**
     * The exact flow captured live from AltoroJ's {@code doLogin}: a POST/redirect/GET flow where
     * {@code doLogin} itself always answers with a bare, empty-bodied 302, and only the {@code
     * Location} differs -- {@code login.jsp} for every failure, including the restrict-verify
     * probe, or {@code bank/main.jsp} for the one payload that actually bypasses the check -- and
     * the scanner follows that redirect, so what the strategy sees is {@code login.jsp}'s or {@code
     * bank/main.jsp}'s own rendered page. A quote alone does not error here (unlike the Derby
     * exception AltoroJ raises elsewhere), so the error-based technique finds nothing and this
     * strategy is the only one that can.
     */
    @Test
    void shouldAlertOnTheExactRedirectFlowCapturedLiveFromAltoroJ() throws Exception {
        // Given
        String doLoginPath = "/altoromutual/doLogin";
        String validUsername = "jsmith";
        nano.addHandler(
                UrlParamValueHandler.builder()
                        .targetPath(doLoginPath)
                        .targetParam("uid")
                        .when(formParam("uid").matches(v -> (validUsername + "' -- ").equals(v)))
                        .withStatus(302)
                        .withHeader(HttpHeader.LOCATION, "/altoromutual/bank/main.jsp")
                        .thenReturn("")
                        .when(formParam("uid").matches(v -> true))
                        .withStatus(302)
                        .withHeader(HttpHeader.LOCATION, "login.jsp")
                        .thenReturn("")
                        .build());
        nano.addHandler(
                UrlParamValueHandler.builder()
                        .targetPath("/altoromutual/login.jsp")
                        .targetParam("uid")
                        .fallbackHtmlResponse(
                                "<html><body><h1>Online Banking Login</h1></body></html>")
                        .build());
        nano.addHandler(
                UrlParamValueHandler.builder()
                        .targetPath("/altoromutual/bank/main.jsp")
                        .targetParam("uid")
                        .fallbackHtmlResponse(
                                "<html><body><h1>Hello John Smith</h1>Welcome to Altoro Mutual"
                                        + " Online.</body></html>")
                        .build());

        // When
        postLogin(doLoginPath, validUsername);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("uid")));
        assertThat(alertsRaised.get(0).getAttack(), is(equalTo("jsmith' -- ")));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                org.hamcrest.Matchers.containsString("Authentication bypassed"));
    }

    /**
     * {@code looksLoggedIn}'s redirect branch only matters when the redirect target is out of
     * the scan's scope, so the real sender never follows it and the strategy sees the bare,
     * empty-bodied 3xx directly. {@code rule.scan()} can't produce that here: the active-scan
     * test harness hardcodes every target as in-scope, so every redirect gets followed
     * regardless of its {@code Location}. Exercising {@code looksLoggedIn} directly (now
     * package-private for this reason) is the only way to cover that branch.
     */
    @Test
    void shouldTreatUnfollowedRedirectAsLoginSuccessWhenLocationLeavesLoginContext()
            throws Exception {
        // Given: baseline redirects back to the login page itself (not a success).
        HttpMessage baseline = getHttpMessage("GET", "/login", "");
        baseline.getResponseHeader().setStatusCode(302);
        baseline.getResponseHeader().setHeader(HttpHeader.LOCATION, "/login.jsp");
        baseline.setResponseBody("");

        // And: the probe redirects to a location naming nothing login-related -- out of scope,
        // so never followed, leaving this bare redirect as the only thing to judge.
        HttpMessage probe = getHttpMessage("GET", "/login", "");
        probe.getResponseHeader().setStatusCode(302);
        probe.getResponseHeader().setHeader(HttpHeader.LOCATION, "http://out-of-scope.example/dashboard");
        probe.setResponseBody("");

        // Then
        assertThat(LoginBypassDetectionStrategy.looksLoggedIn(probe, baseline), is(true));
        // And: judged against itself, the baseline's own redirect is not success evidence.
        assertThat(LoginBypassDetectionStrategy.looksLoggedIn(baseline, baseline), is(false));
    }

    @Test
    void shouldNotAlertWhenUsernameDoesNotExist() throws Exception {
        // Given: the anchored probe only ever reaches rows matching the value already sent, so an
        // unknown username stays unauthenticated regardless of the vulnerability.
        String path = "/altoro/login/";
        nano.addHandler(altoroStyleLoginHandler(path, "jsmith").build());

        // When
        postLogin(path, "nosuchuser");

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldNotAlertAtMediumStrength() throws Exception {
        // Given
        String path = "/altoro/login/";
        nano.addHandler(altoroStyleLoginHandler(path, "jsmith").build());

        // When
        rule.setAttackStrength(AttackStrength.MEDIUM);
        rule.init(formPost(path, "uid=jsmith"), parent);
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldAlertOnGetRequestToo() throws Exception {
        // Given: a login form submitted over GET -- bad practice, but real, and the anchoring
        // safety property holds regardless of method -- so this is not gated on POST.
        String path = "/altoro/login/";
        nano.addHandler(altoroStyleLoginHandler(path, "jsmith").build());
        rule.setAttackStrength(AttackStrength.HIGH);

        // When
        rule.init(getHttpMessage(path + "?uid=jsmith"), parent);
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldNotAlertWhenBaselineIsNotALoginPage() throws Exception {
        // Given: no login/password/auth keyword anywhere in the response.
        String path = "/altoro/search/";
        nano.addHandler(
                UrlParamValueHandler.builder()
                        .targetPath(path)
                        .targetParam("uid")
                        .fallbackHtmlResponse("<html><body>results: none</body></html>")
                        .build());

        // When
        postLogin(path, "jsmith");

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /**
     * "author" and "compass" must not count as "auth" -- the only login keyword either name
     * contains is as a substring, not a whole word.
     */
    @Test
    void shouldNotAlertWhenLoginKeywordIsOnlyASubstringOfAnotherWord() throws Exception {
        // Given
        String path = "/altoro/author-search/";
        nano.addHandler(
                UrlParamValueHandler.builder()
                        .targetPath(path)
                        .targetParam("uid")
                        .when(formParam("uid").matches(v -> "jsmith' -- ".equals(v)))
                        .thenReturnHtml(
                                "<html><body>author: compass guide, home office"
                                        + " supplies</body></html>")
                        .fallbackHtmlResponse("<html><body>author: compass guide</body></html>")
                        .build());

        // When
        postLogin(path, "jsmith");

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /**
     * The success marker must be new, not merely present on the login page too (e.g. a
     * dashboard-style link on the login form itself).
     */
    @Test
    void shouldNotAlertWhenSuccessMarkerAlreadyOnTheBaseline() throws Exception {
        // Given
        String path = "/altoro/home-link/";
        nano.addHandler(
                UrlParamValueHandler.builder()
                        .targetPath(path)
                        .targetParam("uid")
                        .fallbackHtmlResponse(
                                "<html><body>login: <a href=\"/\">home</a></body></html>")
                        .build());

        // When
        postLogin(path, "jsmith");

        // Then
        assertThat(alertsRaised, is(empty()));
    }
}
