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
package org.zaproxy.zap.extension.pscanrulesAlpha.secrets;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import org.junit.jupiter.api.Test;

class GitleaksConfigLoaderUnitTest {

    private static final String BUNDLED =
            "/org/zaproxy/zap/extension/pscanrulesAlpha/resources/gitleaks.toml";
    private static final String FIXTURE =
            "/org/zaproxy/zap/extension/pscanrulesAlpha/secrets/test-gitleaks.toml";

    private static GitleaksConfigLoader.Config load(String resource) throws IOException {
        try (InputStream is = GitleaksConfigLoaderUnitTest.class.getResourceAsStream(resource)) {
            return GitleaksConfigLoader.load(is);
        }
    }

    @Test
    void shouldLoadBundledConfig() throws Exception {
        // Given / When
        GitleaksConfigLoader.Config config = load(BUNDLED);
        // Then
        assertThat(config.rules(), is(not(empty())));
        List<String> ids = config.rules().stream().map(GitleaksRule::getId).toList();
        assertThat(ids, hasItem("aws-access-token"));
        assertThat(config.global(), is(not(equalTo(null))));
    }

    @Test
    void shouldCompileAllBundledPatterns() throws Exception {
        // Given / When
        GitleaksConfigLoader.Config config = load(BUNDLED);
        // Then: every pattern which fails is listed, e.g. when an update adds a pattern which
        // is not supported by re2j.
        assertThat(
                "Patterns not supported by re2j:\n" + String.join("\n", config.failures()),
                config.failures(),
                is(empty()));
    }

    @Test
    void shouldCollectAllFailuresAndSkipTheRules() throws Exception {
        // Given / When
        GitleaksConfigLoader.Config config = load(FIXTURE);
        // Then
        assertThat(config.rules(), hasSize(2));
        assertThat(config.rules().get(0).getId(), is(equalTo("test-token")));
        assertThat(config.failures(), hasSize(3));
        assertThat(config.failures().get(0), startsWith("global allowlist: "));
        assertThat(config.failures().get(1), startsWith("test-incompatible: "));
        assertThat(config.failures().get(2), startsWith("test-bad-allowlist: "));
    }
}
