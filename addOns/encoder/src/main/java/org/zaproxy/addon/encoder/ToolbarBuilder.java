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

import javax.swing.JToolBar;

/**
 * Builds a toolbar for an output panel. Toolbar controls read and write settings via the given
 * {@link OutputPanelContext}; changes should trigger {@link OutputPanelContext#requestReprocess()}.
 */
@FunctionalInterface
public interface ToolbarBuilder {

    /**
     * Builds a toolbar bound to the given context.
     *
     * @param context the panel's context; use for get/set settings and requestReprocess
     * @return a toolbar, never null
     */
    JToolBar buildToolbar(OutputPanelContext context);
}
