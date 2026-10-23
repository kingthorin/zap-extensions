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
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;

/** Extra coverage for volatile CSRF/token normalisation shapes. */
class ResponseBodyUtilsVolatileTest {

    @Test
    void normalisesTokenWhenValuePrecedesName() {
        String input = "<input type=\"hidden\" value=\"aB3dE5fG7hJ9kL1mN4\" name=\"_csrf\"/>";
        assertThat(
                ResponseBodyUtils.stripVolatileTokens(input),
                is("<input type=\"hidden\" value=\"__VOLATILE__\" name=\"_csrf\"/>"));
    }

    @Test
    void normalisesDjangoStyleCsrfMiddlewareToken() {
        String input = "<input name=\"csrfmiddlewaretoken\" value='zY8xW6vU4tS2rQ0pO3nM1qP5rT7' />";
        assertThat(
                ResponseBodyUtils.stripVolatileTokens(input),
                is("<input name=\"csrfmiddlewaretoken\" value='__VOLATILE__' />"));
    }

    @Test
    void normalisesIsoTimestampWithFractionAndZone() {
        String input = "rendered 2026-01-02T15:04:05.123+02:00";
        assertThat(ResponseBodyUtils.stripVolatileTokens(input), is("rendered __VOLATILE__"));
    }

    @Test
    void leavesShortValuesUntouched() {
        String input = "<input name=\"csrf_token\" value=\"short\"/>";
        assertThat(ResponseBodyUtils.stripVolatileTokens(input), is(input));
    }
}
