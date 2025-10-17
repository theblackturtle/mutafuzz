
package com.theblackturtle.mutafuzz.widget;

import javax.swing.Icon;
import javax.swing.JButton;

import java.awt.Color;
import java.awt.Font;

/**
 * A styled button with consistent branding colors and bold font.
 * Uses a distinct background color (#FF6633) with white text.
 */
public class PrimaryButton extends JButton {
    private static final Color BACKGROUND_COLOR = new Color(0xFF6633);
    public static final Color FOREGROUND_COLOR = new Color(0xFFFFFF);

    /**
     * Creates a primary button with default styling.
     */
    public PrimaryButton() {
        this.setupStyle();
    }

    /**
     * Creates a primary button with an icon.
     *
     * @param icon the icon to display
     */
    public PrimaryButton(Icon icon) {
        super(icon);
        this.setupStyle();
    }

    /**
     * Creates a primary button with text label.
     *
     * @param text the text to display
     */
    public PrimaryButton(String text) {
        super(text);
        this.setupStyle();
    }

    /**
     * Applies consistent styling: bold font, branded colors, no borders.
     */
    private void setupStyle() {
        Font currentFont = this.getFont();
        this.setFont(currentFont.deriveFont(1));
        this.setBackground(BACKGROUND_COLOR);
        this.setForeground(FOREGROUND_COLOR);
        this.setOpaque(true);
        this.setContentAreaFilled(true);
        this.setBorderPainted(false);
        this.setFocusPainted(false);
    }

    /**
     * Sets a custom background color, overriding the default branding color.
     *
     * @param color the new background color
     */
    public void setBackgroundColor(Color color) {
        this.setBackground(color);
    }

    /**
     * Sets a custom text color, overriding the default white text.
     *
     * @param color the new text color
     */
    public void setTextColor(Color color) {
        this.setForeground(color);
    }

}
