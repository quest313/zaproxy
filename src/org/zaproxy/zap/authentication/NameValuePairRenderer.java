package org.zaproxy.zap.authentication;

import org.zaproxy.zap.model.NameValuePair;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.plaf.basic.BasicComboBoxRenderer;
import java.awt.*;

/**
 * A renderer for properly displaying the name of a {@link NameValuePair} in a ComboBox.
 *
 * @see #INSTANCE
 */
public class NameValuePairRenderer extends BasicComboBoxRenderer {

    public static final NameValuePairRenderer INSTANCE = new NameValuePairRenderer();

    private static final long serialVersionUID = 3654541772447187317L;
    private static final Border BORDER = new EmptyBorder(2, 3, 3, 3);

    private NameValuePairRenderer() {
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Component getListCellRendererComponent(JList list, Object value, int index,
                                                  boolean isSelected, boolean cellHasFocus) {
        super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
        if (value != null) {
            setBorder(BORDER);
            NameValuePair item = (NameValuePair) value;
            setText(item.getName());
        }
        return this;
    }
}
