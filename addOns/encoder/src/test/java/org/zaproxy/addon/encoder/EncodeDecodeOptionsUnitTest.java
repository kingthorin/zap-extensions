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
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import org.apache.commons.configuration.FileConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;

/** Unit tests for {@link EncodeDecodeOptions} processor settings. */
class EncodeDecodeOptionsUnitTest {

    private static final String PROCESSOR_ID = "encoder.predefined.base64encode";
    private static final String KEY_CHARSET = "base64.charset";

    private EncodeDecodeOptions options;

    @BeforeEach
    void setUp() {
        options = new EncodeDecodeOptions();
    }

    @Test
    void shouldReturnNullProcessorSettingWhenConfigNull() {
        // Given / When
        String value = options.getProcessorSetting(PROCESSOR_ID, KEY_CHARSET);
        // Then
        assertThat(value, is(nullValue()));
    }

    @Test
    void shouldNotThrowWhenSetProcessorSettingAndConfigNull() {
        // When / Then
        assertDoesNotThrow(
                () -> options.setProcessorSetting(PROCESSOR_ID, KEY_CHARSET, "US-ASCII"));
        assertThat(options.getProcessorSetting(PROCESSOR_ID, KEY_CHARSET), is(nullValue()));
    }

    @Test
    void shouldNotThrowWhenClearProcessorSettingAndConfigNull() {
        // When / Then
        assertDoesNotThrow(() -> options.clearProcessorSetting(PROCESSOR_ID, KEY_CHARSET));
        assertThat(options.getProcessorSetting(PROCESSOR_ID, KEY_CHARSET), is(nullValue()));
    }

    @Test
    void shouldReturnProcessorSettingWhenConfigSet() throws Exception {
        // Given
        FileConfiguration config =
                mock(FileConfiguration.class, withSettings().strictness(Strictness.LENIENT));
        given(config.getString("encoder.base64charset", EncodeDecodeOptions.DEFAULT_CHARSET))
                .willReturn(EncodeDecodeOptions.DEFAULT_CHARSET);
        given(
                        config.getBoolean(
                                "encoder.base64dobreaklines",
                                EncodeDecodeOptions.DEFAULT_DO_BREAK_LINES))
                .willReturn(EncodeDecodeOptions.DEFAULT_DO_BREAK_LINES);
        given(
                        config.getBoolean(
                                "encoder.hashers.lowercase",
                                EncodeDecodeOptions.DEFAULT_DO_LOWERCASE))
                .willReturn(EncodeDecodeOptions.DEFAULT_DO_LOWERCASE);
        options.load(config);
        given(
                        config.getString(
                                eq(
                                        "encoder.processor.encoder_predefined_base64encode.base64_charset")))
                .willReturn("ISO-8859-1");
        // When
        String value = options.getProcessorSetting(PROCESSOR_ID, KEY_CHARSET);
        // Then
        assertThat(value, is(equalTo("ISO-8859-1")));
    }

    @Test
    void shouldSetConfigWhenSetProcessorSettingAndConfigLoaded() throws Exception {
        // Given
        FileConfiguration config =
                mock(FileConfiguration.class, withSettings().strictness(Strictness.LENIENT));
        given(config.getString(anyString(), anyString()))
                .willReturn(EncodeDecodeOptions.DEFAULT_CHARSET);
        given(config.getBoolean(anyString(), eq(EncodeDecodeOptions.DEFAULT_DO_BREAK_LINES)))
                .willReturn(EncodeDecodeOptions.DEFAULT_DO_BREAK_LINES);
        given(config.getBoolean(anyString(), eq(EncodeDecodeOptions.DEFAULT_DO_LOWERCASE)))
                .willReturn(EncodeDecodeOptions.DEFAULT_DO_LOWERCASE);
        options.load(config);
        // When
        options.setProcessorSetting(PROCESSOR_ID, KEY_CHARSET, "US-ASCII");
        // Then
        verify(config)
                .setProperty(
                        "encoder.processor.encoder_predefined_base64encode.base64_charset",
                        "US-ASCII");
    }

    @Test
    void shouldClearConfigWhenClearProcessorSettingAndConfigLoaded() throws Exception {
        // Given
        FileConfiguration config =
                mock(FileConfiguration.class, withSettings().strictness(Strictness.LENIENT));
        given(config.getString(anyString(), anyString()))
                .willReturn(EncodeDecodeOptions.DEFAULT_CHARSET);
        given(config.getBoolean(anyString(), eq(EncodeDecodeOptions.DEFAULT_DO_BREAK_LINES)))
                .willReturn(EncodeDecodeOptions.DEFAULT_DO_BREAK_LINES);
        given(config.getBoolean(anyString(), eq(EncodeDecodeOptions.DEFAULT_DO_LOWERCASE)))
                .willReturn(EncodeDecodeOptions.DEFAULT_DO_LOWERCASE);
        options.load(config);
        // When
        options.clearProcessorSetting(PROCESSOR_ID, KEY_CHARSET);
        // Then
        verify(config)
                .clearProperty("encoder.processor.encoder_predefined_base64encode.base64_charset");
    }
}
