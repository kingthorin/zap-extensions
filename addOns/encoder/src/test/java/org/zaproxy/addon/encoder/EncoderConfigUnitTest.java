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
package org.zaproxy.addon.encoder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.closeTo;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link EncoderConfig}. */
class EncoderConfigUnitTest extends TestUtils {

    @BeforeAll
    static void setup() {
        mockMessages(new ExtensionEncoder());
    }

    @BeforeEach
    void setUp() throws Exception {
        Path testHome = Files.createTempDirectory(tempDir, "encoder-test-");
        Constant.setZapHome(testHome.toAbsolutePath().toString());
    }

    @Test
    void shouldReturnDefaultDividerLocationWhenConfigFileDoesNotExist() {
        // Given / When
        double location = EncoderConfig.loadDividerLocation();
        // Then
        assertThat(location, is(closeTo(0.25, 0.001)));
    }

    @Test
    void shouldReturnDefaultDividerLocationWhenConfigHasNoDividerKey() throws Exception {
        // Given
        EncoderConfig.saveConfig(List.of(), null);
        // When
        double location = EncoderConfig.loadDividerLocation();
        // Then
        assertThat(location, is(closeTo(0.25, 0.001)));
    }

    @Test
    void shouldLoadDividerLocationWhenConfigHasValidValue() throws Exception {
        // Given
        double expected = 0.4;
        EncoderConfig.saveConfig(List.of(), expected);
        // When
        double location = EncoderConfig.loadDividerLocation();
        // Then
        assertThat(location, is(closeTo(expected, 0.001)));
    }

    @Test
    void shouldReturnDefaultDividerLocationWhenConfigValueIsOutOfRange() throws Exception {
        // Given
        EncoderConfig.saveConfig(List.of(), 0.5);
        Path configPath =
                Paths.get(Constant.getZapHome(), "addOnData/encoder/config/encoder-config.xml");
        ZapXmlConfiguration config = new ZapXmlConfiguration(configPath.toFile());
        config.setProperty("dividerLocation", 1.5);
        config.save(configPath.toFile());
        // When
        double location = EncoderConfig.loadDividerLocation();
        // Then
        assertThat(location, is(closeTo(0.25, 0.001)));
    }

    @Test
    void shouldPersistAndLoadDividerLocationRoundTrip() throws Exception {
        // Given
        TabModel tab = new TabModel();
        tab.setName("Test");
        double dividerLocation = 0.35;
        // When
        EncoderConfig.saveConfig(List.of(tab), dividerLocation);
        List<TabModel> loadedTabs = EncoderConfig.loadConfig();
        double loadedDivider = EncoderConfig.loadDividerLocation();
        // Then
        assertThat(loadedTabs, hasSize(1));
        assertThat(loadedTabs.get(0).getName(), is(equalTo("Test")));
        assertThat(loadedDivider, is(closeTo(dividerLocation, 0.001)));
    }

    @Test
    void shouldSaveConfigWithoutDividerWhenDividerIsNull() throws Exception {
        // Given / When
        EncoderConfig.saveConfig(List.of());
        double location = EncoderConfig.loadDividerLocation();
        // Then
        assertThat(location, is(closeTo(0.25, 0.001)));
    }

    @Test
    void shouldLoadTabsFromConfigWithDividerPresent() throws Exception {
        // Given
        TabModel tab = new TabModel();
        tab.setName("Encode/Decode/Hash");
        EncoderConfig.saveConfig(List.of(tab), 0.6);
        // When
        List<TabModel> loaded = EncoderConfig.loadConfig();
        // Then
        assertThat(loaded, hasSize(1));
        assertThat(loaded.get(0).getName(), is(equalTo("Encode/Decode/Hash")));
        assertThat(EncoderConfig.loadDividerLocation(), is(closeTo(0.6, 0.001)));
    }

    @Test
    void shouldAcceptDividerLocationAtBoundaries() throws Exception {
        // Given / When
        EncoderConfig.saveConfig(List.of(), 0.0);
        // Then
        assertThat(EncoderConfig.loadDividerLocation(), is(closeTo(0.0, 0.001)));
        // Given / When
        EncoderConfig.saveConfig(List.of(), 1.0);
        // Then
        assertThat(EncoderConfig.loadDividerLocation(), is(closeTo(1.0, 0.001)));
    }
}
