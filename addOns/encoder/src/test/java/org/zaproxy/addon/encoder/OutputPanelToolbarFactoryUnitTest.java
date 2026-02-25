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
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link OutputPanelToolbarFactory}. */
class OutputPanelToolbarFactoryUnitTest {

    private static final String PROCESSOR_ID = "encoder.predefined.base64encode";

    private OutputPanelToolbarFactory factory;
    private OutputPanelContext context;

    @BeforeEach
    void setUp() {
        factory = new OutputPanelToolbarFactory();
        OutputPanelModel model = new OutputPanelModel();
        model.setProcessorId(PROCESSOR_ID);
        context = new OutputPanelContext(model, null, null);
    }

    @Test
    void shouldReturnNullToolbarBuilderWhenNotRegistered() {
        // When
        ToolbarBuilder result = factory.getToolbarBuilder(PROCESSOR_ID);
        // Then
        assertThat(result, is(nullValue()));
    }

    @Test
    void shouldReturnBuilderWhenToolbarBuilderRegistered() {
        // Given
        ToolbarBuilder builder = ctx -> new ToolbarWithRefresh(new javax.swing.JToolBar(), null);
        factory.register(PROCESSOR_ID, builder);
        // When
        ToolbarBuilder result = factory.getToolbarBuilder(PROCESSOR_ID);
        // Then
        assertThat(result, is(equalTo(builder)));
    }

    @Test
    void shouldReturnNullToolbarWhenNoBuilderRegistered() {
        // When
        ToolbarWithRefresh twr = factory.createToolbar(PROCESSOR_ID, context);
        // Then
        assertThat(twr, is(nullValue()));
    }

    @Test
    void shouldReturnToolbarWhenBuilderRegistered() {
        // Given
        javax.swing.JToolBar expectedToolbar = new javax.swing.JToolBar();
        ToolbarBuilder builder = ctx -> new ToolbarWithRefresh(expectedToolbar, null);
        factory.register(PROCESSOR_ID, builder);
        // When
        ToolbarWithRefresh twr = factory.createToolbar(PROCESSOR_ID, context);
        // Then
        assertThat(twr, is(notNullValue()));
        assertThat(twr.getToolbar(), is(equalTo(expectedToolbar)));
    }

    @Test
    void shouldPassContextToBuilderWhenCreateToolbar() {
        // Given
        OutputPanelContext[] captured = new OutputPanelContext[1];
        ToolbarBuilder builder =
                c -> {
                    captured[0] = c;
                    return new ToolbarWithRefresh(new javax.swing.JToolBar(), null);
                };
        factory.register(PROCESSOR_ID, builder);
        // When
        factory.createToolbar(PROCESSOR_ID, context);
        // Then
        assertThat(captured[0], is(equalTo(context)));
    }

    @Test
    void shouldReturnToolbarWithRefreshRunnableWhenBuilderProvidesOne() {
        // Given
        boolean[] refreshed = new boolean[1];
        ToolbarBuilder builder =
                ctx ->
                        new ToolbarWithRefresh(
                                new javax.swing.JToolBar(), () -> refreshed[0] = true);
        factory.register(PROCESSOR_ID, builder);
        ToolbarWithRefresh twr = factory.createToolbar(PROCESSOR_ID, context);
        // When
        twr.refreshFromContext();
        // Then
        assertThat(refreshed[0], is(true));
    }
}
