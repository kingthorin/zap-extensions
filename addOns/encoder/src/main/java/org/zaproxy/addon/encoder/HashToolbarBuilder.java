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

import javax.swing.JCheckBox;
import javax.swing.JToolBar;
import org.parosproxy.paros.Constant;

/** Builds a toolbar for hash panels (lowercase output option). */
public class HashToolbarBuilder implements ToolbarBuilder {

    @Override
    public JToolBar buildToolbar(OutputPanelContext context) {
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        toolbar.setRollover(true);

        JCheckBox lowercaseCheck =
                new JCheckBox(
                        Constant.messages.getString("encoder.toolbar.hashers.output.lowercase"));
        lowercaseCheck.setSelected(context.getBoolean(OutputPanelContext.KEY_HASHERS_LOWERCASE));
        lowercaseCheck.addActionListener(
                e ->
                        context.setSetting(
                                OutputPanelContext.KEY_HASHERS_LOWERCASE,
                                lowercaseCheck.isSelected()));
        toolbar.add(lowercaseCheck);

        return toolbar;
    }
}
