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

import javax.swing.DefaultComboBoxModel;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JToolBar;
import org.parosproxy.paros.Constant;

/** Builds a toolbar for Base64 encode/decode panels (charset and break lines). */
public class Base64ToolbarBuilder implements ToolbarBuilder {

    private static final String[] CHARSETS = {"ISO-8859-1", "US-ASCII", "UTF-8"};

    @Override
    public ToolbarWithRefresh buildToolbar(OutputPanelContext context) {
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        toolbar.setRollover(true);

        toolbar.add(new JLabel(Constant.messages.getString("encoder.toolbar.base64.charset")));
        JComboBox<String> charsetCombo = new JComboBox<>(new DefaultComboBoxModel<>(CHARSETS));
        charsetCombo.setSelectedItem(context.getString(OutputPanelContext.KEY_BASE64_CHARSET));
        java.awt.event.ActionListener charsetListener =
                e ->
                        context.setSetting(
                                OutputPanelContext.KEY_BASE64_CHARSET,
                                (String) charsetCombo.getSelectedItem());
        charsetCombo.addActionListener(charsetListener);
        toolbar.add(charsetCombo);

        toolbar.addSeparator();

        JCheckBox breakLinesCheck =
                new JCheckBox(Constant.messages.getString("encoder.toolbar.base64.breaklines"));
        breakLinesCheck.setSelected(context.getBoolean(OutputPanelContext.KEY_BASE64_BREAK_LINES));
        java.awt.event.ActionListener breakLinesListener =
                e ->
                        context.setSetting(
                                OutputPanelContext.KEY_BASE64_BREAK_LINES,
                                breakLinesCheck.isSelected());
        breakLinesCheck.addActionListener(breakLinesListener);
        toolbar.add(breakLinesCheck);

        Runnable refresh =
                () -> {
                    charsetCombo.removeActionListener(charsetListener);
                    charsetCombo.setSelectedItem(
                            context.getString(OutputPanelContext.KEY_BASE64_CHARSET));
                    charsetCombo.addActionListener(charsetListener);
                    breakLinesCheck.removeActionListener(breakLinesListener);
                    breakLinesCheck.setSelected(
                            context.getBoolean(OutputPanelContext.KEY_BASE64_BREAK_LINES));
                    breakLinesCheck.addActionListener(breakLinesListener);
                };
        return new ToolbarWithRefresh(toolbar, refresh);
    }
}
