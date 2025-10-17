package com.theblackturtle.mutafuzz.util;

import java.text.DecimalFormat;
import java.util.Random;

/**
 * Provides string manipulation, random data generation, and formatting utilities.
 * Supports line/word counting, random identifiers, file size formatting, and line ending normalization.
 */
public class Utils {
    private static final String CHARSET = "0123456789abcdefghijklmnopqrstuvwxyz";
    private static final String START_CHARSET = "ghijklmnopqrstuvwxyz";
    private static final String NUMBER_CHARSET = "0123456789";
    static Random rnd = new Random();

    /**
     * Counts the number of lines in a string.
     * Handles both LF (\n) and CR (\r) line endings.
     *
     * @param str Input string
     * @return Number of lines, or 0 if null or empty
     */
    public static int countLines(String str) {
        if (str == null || str.isEmpty()) {
            return 0;
        }

        int lines = 1;
        for (int i = 0; i < str.length(); i++) {
            char ch = str.charAt(i);
            if (ch == '\n' || (ch == '\r' && (i + 1 == str.length() || str.charAt(i + 1) != '\n'))) {
                lines++;
            }
        }

        return lines;
    }

    /**
     * Counts the number of words in a string.
     * Words are defined as sequences of letters or digits separated by non-alphanumeric characters.
     *
     * @param str Input string
     * @return Number of words, or 0 if null or empty
     */
    public static int countWords(String str) {
        if (str == null || str.isEmpty()) {
            return 0;
        }

        int wordCount = 0;
        boolean isWord = false;
        int endOfLine = str.length() - 1;

        for (int i = 0; i < str.length(); i++) {
            if (Character.isLetterOrDigit(str.charAt(i)) && i != endOfLine) {
                isWord = true;
            } else if (!Character.isLetterOrDigit(str.charAt(i)) && isWord) {
                wordCount++;
                isWord = false;
            } else if (Character.isLetterOrDigit(str.charAt(i)) && i == endOfLine) {
                wordCount++;
            }
        }
        return wordCount;
    }

    /**
     * Generates a random alphanumeric string.
     * First character is always a letter to ensure valid identifier format.
     * Uses lowercase only to avoid case sensitivity issues.
     *
     * @param len Desired length (minimum 1)
     * @return Random alphanumeric string
     */
    public static String randomString(int len) {
        StringBuilder sb = new StringBuilder(len);
        sb.append(START_CHARSET.charAt(rnd.nextInt(START_CHARSET.length())));
        for (int i = 1; i < len; i++)
            sb.append(CHARSET.charAt(rnd.nextInt(CHARSET.length())));
        return sb.toString();
    }

    /**
     * Generates a random numeric string.
     *
     * @param len Desired length (minimum 1)
     * @return Random numeric string
     */
    public static String randomNumber(int len) {
        StringBuilder sb = new StringBuilder(len);
        sb.append(NUMBER_CHARSET.charAt(rnd.nextInt(NUMBER_CHARSET.length())));
        for (int i = 1; i < len; i++)
            sb.append(NUMBER_CHARSET.charAt(rnd.nextInt(NUMBER_CHARSET.length())));
        return sb.toString();
    }

    /**
     * Generates a random integer within the inclusive range [min, max].
     *
     * @param min Lower bound (inclusive)
     * @param max Upper bound (inclusive)
     * @return Random number as a string
     */
    public static String randomNumber(int min, int max) {
        return Integer.toString(rnd.nextInt(max - min + 1) + min);
    }

    /**
     * Normalizes all line endings to Unix-style LF.
     * Handles both Windows (CRLF) and legacy Mac (CR) line endings.
     *
     * @param str Input string
     * @return String with normalized line endings
     */
    public static String normalizeLineEndings(String str) {
        return str.replaceAll("\\r\\n?", "\n");
    }

    /**
     * Formats byte size into human-readable string with appropriate unit.
     * Units: B, KB, MB, GB, TB
     *
     * @param size Size in bytes
     * @return Formatted string with unit (e.g., "1.5 MB")
     */
    public static String readableFileSize(long size) {
        if (size <= 0)
            return "0";
        final String[] units = new String[] { "B", "KB", "MB", "GB", "TB" };
        int digitGroups = (int) (Math.log10(size) / Math.log10(1024));
        return new DecimalFormat("#,##0.#").format(size / Math.pow(1024, digitGroups)) + units[digitGroups];
    }
}
