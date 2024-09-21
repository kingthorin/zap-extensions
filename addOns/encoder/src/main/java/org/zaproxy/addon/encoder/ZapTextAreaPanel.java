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
package org.zaproxy.addon.encoder;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.BoxLayout;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.text.Document;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.ZapTextArea;

public class ZapTextAreaPanel extends JPanel {
    public static final String ENCODER_COMP = "EncoderComponent";
    private static final long serialVersionUID = 1L;

    private ZapTextArea zta = new ZapTextArea(30, 30);

    public ZapTextAreaPanel() {
        this.setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        zta.setName(ENCODER_COMP);
        zta.setVisible(true);
        zta.addMouseListener(
                new MouseAdapter() {
                    @Override
                    public void mousePressed(MouseEvent e) {
                        if (SwingUtilities.isRightMouseButton(e)) {
                            View.getSingleton()
                                    .getPopupMenu()
                                    .show(e.getComponent(), e.getX(), e.getY());
                        }
                    }
                });
        this.add(zta);
    }

    public void setLineWrap(boolean wrap) {
        zta.setLineWrap(wrap);
    }

    public void setEditable(boolean editable) {
        zta.setEditable(editable);
    }

    public String getText() {
        return zta.getText();
    }

    public void setText(String text) {
        zta.setText(text);
        zta.repaint();
    }

    public Document getDocument() {
        return zta.getDocument();
    }

    public String getSelectedText() {
        return zta.getSelectedText();
    }
}
