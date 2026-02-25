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
 * A toolbar and an optional runnable to refresh its controls from the panel context. Used so that
 * when the same processor is on multiple panels, changing a setting on one panel can refresh the
 * others without rebuilding the toolbar.
 */
public final class ToolbarWithRefresh {

    private final JToolBar toolbar;
    private final Runnable refresh;

    public ToolbarWithRefresh(JToolBar toolbar, Runnable refresh) {
        this.toolbar = toolbar;
        this.refresh = refresh;
    }

    public JToolBar getToolbar() {
        return toolbar;
    }

    /** Runs the refresh runnable if present (e.g. to sync from context). No-op if null. */
    public void refreshFromContext() {
        if (refresh != null) {
            refresh.run();
        }
    }
}
