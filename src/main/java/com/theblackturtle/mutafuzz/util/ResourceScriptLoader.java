package com.theblackturtle.mutafuzz.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

/**
 * Loads bundled Python scripts from JAR resources.
 * Provides fallback mechanism when file system script directory is unavailable.
 */
public class ResourceScriptLoader {
    private static final Logger LOGGER = LoggerFactory.getLogger(ResourceScriptLoader.class);

    private static final String RESOURCE_PATH = "/scripts/";
    private static final String RESOURCE_PATH_NO_LEADING_SLASH = "scripts/";

    /**
     * Loads all bundled scripts from JAR resources.
     * Automatically discovers all .py files in the /scripts/ directory.
     *
     * @return Map of script name to content (missing scripts are logged but excluded)
     */
    public static Map<String, String> loadBundledScripts() {
        Map<String, String> scripts = new HashMap<>();
        List<String> scriptNames = discoverScriptsInResources();

        for (String scriptName : scriptNames) {
            String content = loadScript(scriptName);
            if (content != null) {
                scripts.put(scriptName, content);
                LOGGER.debug("Loaded bundled script: {}", scriptName);
            } else {
                LOGGER.warn("Failed to load bundled script: {}", scriptName);
            }
        }

        LOGGER.info("Loaded {} bundled scripts from JAR resources", scripts.size());
        return scripts;
    }

    /**
     * Discovers all .py files in the /scripts/ resource directory.
     * Handles both file system (IDE) and JAR (production) environments.
     *
     * @return Sorted list of script filenames
     */
    private static List<String> discoverScriptsInResources() {
        List<String> scriptNames = new ArrayList<>();

        try {
            URL resourceUrl = ResourceScriptLoader.class.getResource(RESOURCE_PATH);

            if (resourceUrl == null) {
                LOGGER.warn("Resource directory not found: {}", RESOURCE_PATH);
                return scriptNames;
            }

            String protocol = resourceUrl.getProtocol();

            if ("file".equals(protocol)) {
                scriptNames = discoverScriptsFromFileSystem(resourceUrl);
            } else if ("jar".equals(protocol)) {
                scriptNames = discoverScriptsFromJar(resourceUrl);
            } else {
                LOGGER.warn("Unsupported protocol for resource discovery: {}", protocol);
            }

            Collections.sort(scriptNames);
            LOGGER.debug("Discovered {} Python scripts in {}", scriptNames.size(), RESOURCE_PATH);

        } catch (Exception e) {
            LOGGER.error("Error discovering scripts in resources: {}", e.getMessage(), e);
        }

        return scriptNames;
    }

    /**
     * Discovers scripts from file system in development/IDE environment.
     *
     * @param resourceUrl URL pointing to the scripts directory
     * @return List of discovered script filenames
     */
    private static List<String> discoverScriptsFromFileSystem(URL resourceUrl) {
        List<String> scriptNames = new ArrayList<>();

        try {
            File directory = new File(resourceUrl.toURI());
            if (directory.isDirectory()) {
                File[] files = directory.listFiles((dir, name) -> name.endsWith(".py"));
                if (files != null) {
                    for (File file : files) {
                        scriptNames.add(file.getName());
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.error("Error discovering scripts from file system: {}", e.getMessage(), e);
        }

        return scriptNames;
    }

    /**
     * Discovers scripts from JAR file in production environment.
     *
     * @param resourceUrl URL pointing to the scripts directory inside JAR
     * @return List of discovered script filenames
     */
    private static List<String> discoverScriptsFromJar(URL resourceUrl) {
        List<String> scriptNames = new ArrayList<>();

        try {
            String jarPath = resourceUrl.getPath();
            int separatorIndex = jarPath.indexOf("!");
            if (separatorIndex > 0) {
                jarPath = jarPath.substring(0, separatorIndex);
                if (jarPath.startsWith("file:")) {
                    jarPath = jarPath.substring(5);
                }
            }

            jarPath = URLDecoder.decode(jarPath, StandardCharsets.UTF_8.name());

            try (JarFile jarFile = new JarFile(jarPath)) {
                Enumeration<JarEntry> entries = jarFile.entries();

                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    String entryName = entry.getName();

                    if (entryName.startsWith(RESOURCE_PATH_NO_LEADING_SLASH) &&
                        entryName.endsWith(".py") &&
                        !entry.isDirectory()) {

                        String fileName = entryName.substring(RESOURCE_PATH_NO_LEADING_SLASH.length());

                        if (!fileName.contains("/")) {
                            scriptNames.add(fileName);
                        }
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.error("Error discovering scripts from JAR: {}", e.getMessage(), e);
        }

        return scriptNames;
    }

    /**
     * Loads a single script from JAR resources.
     *
     * @param scriptName Name of the script file
     * @return Script content, or null if not found or error occurs
     */
    private static String loadScript(String scriptName) {
        String resourcePath = RESOURCE_PATH + scriptName;

        try (InputStream inputStream = ResourceScriptLoader.class.getResourceAsStream(resourcePath)) {
            if (inputStream == null) {
                LOGGER.warn("Resource not found: {}", resourcePath);
                return null;
            }

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                return reader.lines().collect(Collectors.joining("\n"));
            }
        } catch (Exception e) {
            LOGGER.error("Error reading script resource {}: {}", resourcePath, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Checks if bundled scripts are available in JAR.
     *
     * @return true if scripts directory exists in resources
     */
    public static boolean areBundledScriptsAvailable() {
        try {
            URL resourceUrl = ResourceScriptLoader.class.getResource(RESOURCE_PATH);
            return resourceUrl != null;
        } catch (Exception e) {
            LOGGER.debug("Bundled scripts not available: {}", e.getMessage());
            return false;
        }
    }
}
