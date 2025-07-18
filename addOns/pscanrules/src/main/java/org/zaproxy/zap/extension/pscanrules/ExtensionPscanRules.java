/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;

/**
 * A null extension just to cause the message bundle and help file to get loaded
 *
 * @author psiinon
 */
public class ExtensionPscanRules extends ExtensionAdaptor {

    @Override
    public String getName() {
        return "ExtensionPscanRules";
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("pscanrules.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("pscanrules.desc");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        extensionHook.addSessionListener(new PscanSessionChangedListener());
    }

    private static class PscanSessionChangedListener implements SessionChangedListener {

        @Override
        public void sessionChanged(Session session) {
            ZapVersionScanRule.clear();
        }

        @Override
        public void sessionAboutToChange(Session session) {}

        @Override
        public void sessionScopeChanged(Session session) {}

        @Override
        public void sessionModeChanged(Mode mode) {}
    }
}
