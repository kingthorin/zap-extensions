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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry mapping processor IDs to {@link ToolbarBuilder}s. Creates toolbars on demand when output
 * panels are added. Returns null for processors without custom toolbars (graceful degradation).
 */
public class OutputPanelToolbarFactory {

    private final Map<String, ToolbarBuilder> builders = new ConcurrentHashMap<>();

    /**
     * Registers a toolbar builder for the given processor ID.
     *
     * @param processorId e.g. {@link
     *     org.zaproxy.addon.encoder.processors.EncodeDecodeProcessors#PREDEFINED_PREFIX} +
     *     "base64encode"
     * @param builder the builder to use for that processor
     */
    public void register(String processorId, ToolbarBuilder builder) {
        builders.put(processorId, builder);
    }

    /** Returns the toolbar builder for the processor ID, or null if none is registered. */
    public ToolbarBuilder getToolbarBuilder(String processorId) {
        return builders.get(processorId);
    }

    /**
     * Creates a toolbar for the given processor and context. Returns null if no builder is
     * registered for the processor.
     *
     * @param processorId the panel's processor ID
     * @param context the panel's context
     * @return a new toolbar with optional refresh, or null
     */
    public ToolbarWithRefresh createToolbar(String processorId, OutputPanelContext context) {
        ToolbarBuilder builder = builders.get(processorId);
        if (builder == null) {
            return null;
        }
        return builder.buildToolbar(context);
    }
}
