package org.zaproxy.addon.encoder;
import javax.swing.BoxLayout;
import javax.swing.JPanel;
import javax.swing.text.Document;

import org.zaproxy.zap.utils.ZapTextArea;

public class ZapTextAreaPanel extends JPanel {
    private static final long serialVersionUID = 1L;
    
    private ZapTextArea zta;

    public ZapTextAreaPanel() {
        this.setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        this.zta = new ZapTextArea(30,30);
        zta.setVisible(true);
        this.add(zta);
        zta.setText("jane");
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
        zta.updateUI();
    }
    
    public Document getDocument()
    {
        return zta.getDocument();
    }
}
