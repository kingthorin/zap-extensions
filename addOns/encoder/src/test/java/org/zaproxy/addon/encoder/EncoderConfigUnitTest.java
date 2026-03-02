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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link EncoderConfig} (tabs, divider location, processor settings). */
class EncoderConfigUnitTest extends TestUtils {

    private static final String CONFIG_PATH = "addOnData/encoder/config/encoder-config.json";

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
    }

    @Test
    void shouldHaveDefaultDividerLocationWhenNoConfigFile() throws Exception {
        // Given no config file (loadConfig will use loadDefaultConfig)
        // When
        EncoderConfig.Data data = EncoderConfig.loadConfig();
        // Then
        assertThat(
                data.getDividerLocation(),
                is(equalTo(EncoderConfig.Data.DEFAULT_DIVIDER_LOCATION)));
    }

    @Test
    void loadDefaultConfigShouldReturnBundledTabsAndDivider() throws Exception {
        // When
        EncoderConfig.Data data = EncoderConfig.loadDefaultConfig();
        // Then
        assertThat(data.getDividerLocation(), is(equalTo(EncoderConfig.Data.DEFAULT_DIVIDER_LOCATION)));
        assertThat(data.getTabs().isEmpty(), is(equalTo(false)));
    }

    @Test
    void noArgDataShouldHaveDefaultDividerAndEmptyTabs() {
        EncoderConfig.Data data = new EncoderConfig.Data();
        assertThat(data.getDividerLocation(), is(equalTo(EncoderConfig.Data.DEFAULT_DIVIDER_LOCATION)));
        assertThat(data.getTabs().isEmpty(), is(equalTo(true)));
    }

    @Test
    void shouldSaveAndLoadDividerLocation() throws Exception {
        // Given
        List<TabModel> tabs = new ArrayList<>();
        double value = 0.35;
        // When
        EncoderConfig.saveConfig(new EncoderConfig.Data(tabs, value));
        // Then
        EncoderConfig.Data data = EncoderConfig.loadConfig();
        assertThat(data.getDividerLocation(), is(equalTo(value)));
    }

    @Test
    void shouldUseDefaultWhenDividerLocationInFileOutOfRange() throws Exception {
        // Given
        Path configFile = Paths.get(Constant.getZapHome(), CONFIG_PATH);
        Files.createDirectories(configFile.getParent());
        String json = "{\"tabs\":[],\"dividerLocation\":1.5,\"processorSettings\":{}}";
        Files.write(configFile, json.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        // When
        EncoderConfig.Data data = EncoderConfig.loadConfig();
        // Then
        assertThat(
                data.getDividerLocation(),
                is(equalTo(EncoderConfig.Data.DEFAULT_DIVIDER_LOCATION)));
    }

    @Test
    void shouldRoundTripProcessorSettings() throws Exception {
        EncoderConfig.Data data = new EncoderConfig.Data();
        data.setProcessorSetting("encoder.predefined.base64encode", "base64.charset", "ISO-8859-1");
        data.setProcessorSetting("encoder.predefined.base64encode", "base64.breakLines", "false");
        EncoderConfig.saveConfig(data);
        EncoderConfig.Data loaded = EncoderConfig.loadConfig();
        assertThat(loaded.getProcessorSetting("encoder.predefined.base64encode", "base64.charset"), is(equalTo("ISO-8859-1")));
        assertThat(loaded.getProcessorSetting("encoder.predefined.base64encode", "base64.breakLines"), is(equalTo("false")));
    }

    @ParameterizedTest
    @MethodSource("dataDividerLocationArgs")
    void dataUsesDefaultWhenDividerLocationOutOfRange(double raw, double expected) {
        // Given
        List<TabModel> tabs = List.of();
        // When
        EncoderConfig.Data data = new EncoderConfig.Data(tabs, raw);
        // Then
        assertThat(data.getDividerLocation(), is(equalTo(expected)));
    }

    static Stream<Arguments> dataDividerLocationArgs() {
        double d = EncoderConfig.Data.DEFAULT_DIVIDER_LOCATION;
        return Stream.of(
                Arguments.of(-0.1, d),
                Arguments.of(0.0, 0.0),
                Arguments.of(0.35, 0.35),
                Arguments.of(1.0, 1.0),
                Arguments.of(1.5, d));
    }
}
