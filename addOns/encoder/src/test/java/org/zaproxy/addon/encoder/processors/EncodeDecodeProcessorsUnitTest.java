/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.encoder.processors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.encoder.EncodeDecodeOptions;
import org.zaproxy.addon.encoder.ExtensionEncoder;
import org.zaproxy.addon.encoder.OutputPanelContext;
import org.zaproxy.addon.encoder.OutputPanelModel;
import org.zaproxy.addon.encoder.OutputPanelToolbarFactory;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link EncodeDecodeProcessors}. */
public class EncodeDecodeProcessorsUnitTest extends TestUtils {

    @BeforeAll
    static void setup() {
        mockMessages(new ExtensionEncoder());
    }

    @BeforeEach
    void setUpControl() {
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionEncoder extEnc =
                mock(ExtensionEncoder.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionScript extensionScript =
                mock(ExtensionScript.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionEncoder.class)).willReturn(extEnc);
        given(extensionLoader.getExtension(ExtensionScript.class)).willReturn(extensionScript);
        given(extensionScript.getScripts(ExtensionEncoder.SCRIPT_TYPE_ENCODE_DECODE))
                .willReturn(Collections.emptyList());
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        EncodeDecodeOptions options =
                mock(EncodeDecodeOptions.class, withSettings().strictness(Strictness.LENIENT));
        given(extEnc.getOptions()).willReturn(options);
        given(options.getBase64Charset()).willReturn(EncodeDecodeOptions.DEFAULT_CHARSET);
        given(options.isBase64DoBreakLines())
                .willReturn(EncodeDecodeOptions.DEFAULT_DO_BREAK_LINES);
        given(options.isHashersLowerCase()).willReturn(EncodeDecodeOptions.DEFAULT_DO_LOWERCASE);
    }

    @Test
    void shouldLoadPredefinedProcessors() {
        // Given / When
        List<EncodeDecodeProcessorItem> processors =
                EncodeDecodeProcessors.getPredefinedProcessors();
        // Then
        assertThat(processors, hasSize(31));
    }

    @Test
    void shouldReturnFactoryWithBase64AndHashBuildersRegistered() {
        // When
        OutputPanelToolbarFactory factory = EncodeDecodeProcessors.getToolbarFactory();
        // Then
        assertThat(
                factory.getToolbarBuilder(
                        EncodeDecodeProcessors.PREDEFINED_PREFIX + "base64encode"),
                is(notNullValue()));
        assertThat(
                factory.getToolbarBuilder(
                        EncodeDecodeProcessors.PREDEFINED_PREFIX + "base64decode"),
                is(notNullValue()));
        assertThat(
                factory.getToolbarBuilder(EncodeDecodeProcessors.PREDEFINED_PREFIX + "md5hash"),
                is(notNullValue()));
        assertThat(
                factory.getToolbarBuilder(EncodeDecodeProcessors.PREDEFINED_PREFIX + "sha1hash"),
                is(notNullValue()));
        assertThat(
                factory.getToolbarBuilder(EncodeDecodeProcessors.PREDEFINED_PREFIX + "sha256hash"),
                is(notNullValue()));
    }

    @Test
    void shouldForwardContextToProcessorWhenProcess() throws Exception {
        // Given
        EncodeDecodeProcessors processors = new EncodeDecodeProcessors();
        String processorId = EncodeDecodeProcessors.PREDEFINED_PREFIX + "md5hash";
        OutputPanelModel model = new OutputPanelModel();
        model.setProcessorId(processorId);
        OutputPanelContext context = new OutputPanelContext(model, null, null);
        context.setSetting(OutputPanelContext.KEY_HASHERS_LOWERCASE, true);
        // When
        EncodeDecodeResult result = processors.process(processorId, "admin", context);
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(result.getResult(), is(equalTo("21232f297a57a5a743894a0e4a801fc3")));
    }

    @Test
    void shouldUseGlobalOptionsWhenProcessWithNullContext() throws Exception {
        // Given
        EncodeDecodeProcessors processors = new EncodeDecodeProcessors();
        String processorId = EncodeDecodeProcessors.PREDEFINED_PREFIX + "base64encode";
        // When
        EncodeDecodeResult result = processors.process(processorId, "admin", null);
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(result.getResult(), is(equalTo("YWRtaW4=")));
    }
}
