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
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;

/** Unit tests for {@link OutputPanelContext}. */
class OutputPanelContextUnitTest {

    private OutputPanelModel panelModel;
    private EncodeDecodeOptions globalOptions;
    private Runnable reprocessCallback;

    @BeforeEach
    void setUp() {
        panelModel = new OutputPanelModel();
        panelModel.setProcessorId("encoder.predefined.base64encode");
        panelModel.setName("Base64 Encode");
        globalOptions =
                mock(EncodeDecodeOptions.class, withSettings().strictness(Strictness.LENIENT));
        reprocessCallback = mock(Runnable.class);
    }

    @Test
    void shouldReturnInstanceValueFirstForGetString() {
        // Given
        EncoderConfig.Data store = new EncoderConfig.Data();
        OutputPanelContext ctx =
                new OutputPanelContext(panelModel, store, globalOptions, reprocessCallback);
        ctx.setSetting(OutputPanelContext.KEY_BASE64_CHARSET, "US-ASCII");
        // When
        String value = ctx.getString(OutputPanelContext.KEY_BASE64_CHARSET);
        // Then
        assertThat(value, is(equalTo("US-ASCII")));
    }

    @Test
    void shouldFallBackToProcessorOverrideForGetStringWhenInstanceNotSet() {
        // Given
        EncoderConfig.Data store = new EncoderConfig.Data();
        store.setProcessorSetting(panelModel.getProcessorId(), "base64.charset", "ISO-8859-1");
        OutputPanelContext ctx =
                new OutputPanelContext(panelModel, store, globalOptions, reprocessCallback);
        // When
        String value = ctx.getString(OutputPanelContext.KEY_BASE64_CHARSET);
        // Then
        assertThat(value, is(equalTo("ISO-8859-1")));
    }

    @Test
    void shouldFallBackToGlobalDefaultForGetStringWhenNoOverride() {
        // Given
        given(globalOptions.getBase64Charset()).willReturn("UTF-8");
        EncoderConfig.Data store = new EncoderConfig.Data();
        OutputPanelContext ctx =
                new OutputPanelContext(panelModel, store, globalOptions, reprocessCallback);
        // When
        String value = ctx.getString(OutputPanelContext.KEY_BASE64_CHARSET);
        // Then
        assertThat(value, is(equalTo("UTF-8")));
    }

    @Test
    void shouldFallBackToHardDefaultForGetStringWhenGlobalOptionsNull() {
        // Given
        OutputPanelContext ctx =
                new OutputPanelContext(panelModel, new EncoderConfig.Data(), null, reprocessCallback);
        // When
        String value = ctx.getString(OutputPanelContext.KEY_BASE64_CHARSET);
        // Then
        assertThat(value, is(equalTo(EncodeDecodeOptions.DEFAULT_CHARSET)));
    }

    @Test
    void shouldReturnInstanceValueFirstForGetBoolean() {
        // Given
        EncoderConfig.Data store = new EncoderConfig.Data();
        OutputPanelContext ctx =
                new OutputPanelContext(panelModel, store, globalOptions, reprocessCallback);
        ctx.setSetting(OutputPanelContext.KEY_BASE64_BREAK_LINES, false);
        // When
        boolean value = ctx.getBoolean(OutputPanelContext.KEY_BASE64_BREAK_LINES);
        // Then
        assertThat(value, is(equalTo(false)));
    }

    @Test
    void shouldFallBackToHardDefaultForHashersWhenGlobalOptionsNull() {
        // Given
        OutputPanelContext ctx =
                new OutputPanelContext(panelModel, new EncoderConfig.Data(), null, reprocessCallback);
        // When
        boolean value = ctx.getBoolean(OutputPanelContext.KEY_HASHERS_LOWERCASE);
        // Then
        assertThat(value, is(equalTo(EncodeDecodeOptions.DEFAULT_DO_LOWERCASE)));
    }

    @Test
    void shouldInvokeCallbackWhenRequestReprocess() {
        // Given
        EncoderConfig.Data store = new EncoderConfig.Data();
        OutputPanelContext ctx =
                new OutputPanelContext(panelModel, store, globalOptions, reprocessCallback);
        // When
        ctx.requestReprocess();
        // Then
        verify(reprocessCallback).run();
    }

    @Test
    void shouldNotThrowWhenRequestReprocessAndCallbackNull() {
        // Given
        EncoderConfig.Data store = new EncoderConfig.Data();
        OutputPanelContext ctx =
                new OutputPanelContext(panelModel, store, globalOptions, null);
        // When
        ctx.requestReprocess();
        // Then
        assertThat(
                ctx.getString(OutputPanelContext.KEY_BASE64_CHARSET),
                is(equalTo(EncodeDecodeOptions.DEFAULT_CHARSET)));
    }

    @Test
    void shouldInvokeReprocessCallbackWhenSetSetting() {
        // Given
        given(globalOptions.getBase64Charset()).willReturn(EncodeDecodeOptions.DEFAULT_CHARSET);
        EncoderConfig.Data store = new EncoderConfig.Data();
        OutputPanelContext ctx =
                new OutputPanelContext(panelModel, store, globalOptions, reprocessCallback);
        // When
        ctx.setSetting(OutputPanelContext.KEY_BASE64_CHARSET, "UTF-8");
        // Then
        verify(reprocessCallback).run();
    }
}
