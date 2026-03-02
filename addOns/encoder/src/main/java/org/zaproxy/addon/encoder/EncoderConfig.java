/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class EncoderConfig {

    private static final Logger LOGGER = LogManager.getLogger(EncoderConfig.class);

    private static final String CONFIG_BASE = "addOnData/encoder/config/";
    private static final String CONFIG_FILE = CONFIG_BASE + "encoder-config.json";
    private static final String CONFIG_FILE_XML = CONFIG_BASE + "encoder-config.xml";
    private static final String DEFAULT_CONFIG_FILE_NAME = "encoder-default.json";
    private static final String DEFAULT_BUNDLED_CONFIG_FILE = "resources/" + DEFAULT_CONFIG_FILE_NAME;

    private static final String TABS_KEY = "tabs";
    private static final String TAB_KEY = "tab";
    private static final String TAB_PATH = TABS_KEY + "." + TAB_KEY;
    private static final String OUTPUT_PANELS_KEY = "outputpanels";
    private static final String OUTPUT_PANEL_KEY = "outputpanel";
    private static final String OUTPUT_PANEL_PATH = OUTPUT_PANELS_KEY + "." + OUTPUT_PANEL_KEY;
    private static final String TAB_NAME_KEY = "name";
    private static final String OUTPUT_PANEL_NAME_KEY = "name";
    private static final String OUTPUT_PANEL_SCRIPT_KEY = "processorId";
    private static final String DIVIDER_LOCATION_KEY = "dividerLocation";

    private static final ObjectMapper OBJECT_MAPPER =
            new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private EncoderConfig() {
        // Utility Class
    }

    public static Data loadConfig() throws ConfigurationException, IOException {
        Path configPath = getConfigPath(CONFIG_FILE);
        Path configPathXml = getConfigPath(CONFIG_FILE_XML);

        if (Files.exists(configPath)) {
            return loadConfigFromJson(configPath);
        }
        if (Files.exists(configPathXml)) {
            Data data = loadConfigFromXml(configPathXml);
            saveConfig(data);
            try {
                Files.delete(configPathXml);
            } catch (IOException e) {
                LOGGER.warn("Could not remove legacy config file {}", configPathXml, e);
            }
            return data;
        }
        return loadDefaultConfig();
    }

    /**
     * Loads the default config from the bundled resource only. Does not write to disk. Used for
     * first run and for reset.
     */
    public static Data loadDefaultConfig() throws ConfigurationException, IOException {
        try (InputStream in =
                EncoderConfig.class.getResourceAsStream(DEFAULT_BUNDLED_CONFIG_FILE)) {
            if (in == null) {
                LOGGER.error("Bundled config resource not found: {}", DEFAULT_BUNDLED_CONFIG_FILE);
                return new Data();
            }
            return OBJECT_MAPPER.readValue(in, Data.class);
        } catch (JsonProcessingException e) {
            LOGGER.error("Failed to parse bundled encoder config", e);
            return new Data();
        }
    }

    private static Path getConfigPath(String configName) {
        return Paths.get(Constant.getZapHome(), configName);
    }

    static Data loadConfigFromJson(Path file) throws IOException {
        Data data = OBJECT_MAPPER.readValue(file.toFile(), Data.class);
        if (data.getProcessorSettings() == null) {
            data.setProcessorSettings(new HashMap<>());
        }
        data.validateDividerLocation();
        return data;
    }

    public static void saveConfig(Data data) throws ConfigurationException, IOException {
        Path path = getConfigPath(CONFIG_FILE);
        Files.createDirectories(path.getParent());
        OBJECT_MAPPER.writeValue(path.toFile(), data);
    }

    /**
     * One-time migration from legacy XML config. Reads tabs and divider only; processorSettings
     * remain empty.
     */
    private static Data loadConfigFromXml(Path file) throws ConfigurationException {
        ZapXmlConfiguration config = new ZapXmlConfiguration(file.toFile());
        List<TabModel> tabs = new ArrayList<>();
        List<HierarchicalConfiguration> tabConfigs = config.configurationsAt(TAB_PATH);
        for (HierarchicalConfiguration tabConfig : tabConfigs) {
            String tabName = tabConfig.getString(TAB_NAME_KEY);
            TabModel tab = new TabModel();
            tab.setName(tabName);

            List<OutputPanelModel> panels = new ArrayList<>();
            List<HierarchicalConfiguration> panelConfigs =
                    tabConfig.configurationsAt(OUTPUT_PANEL_PATH);
            for (HierarchicalConfiguration panelConfig : panelConfigs) {
                String panelName = panelConfig.getString(OUTPUT_PANEL_NAME_KEY);
                String script = panelConfig.getString(OUTPUT_PANEL_SCRIPT_KEY);
                OutputPanelModel panel = new OutputPanelModel();
                panel.setName(panelName);
                panel.setProcessorId(script);
                panels.add(panel);
            }

            tab.setOutputPanels(panels);
            tabs.add(tab);
        }
        double dividerLocation =
                config.getDouble(DIVIDER_LOCATION_KEY, Data.DEFAULT_DIVIDER_LOCATION);
        Data data = new Data(tabs, dividerLocation);
        data.setProcessorSettings(new HashMap<>());
        return data;
    }

    /** Holder for encoder config: tab layout, divider position, and per-processor toolbar settings. */
    public static final class Data implements ProcessorSettingStore {

        /** Default proportion (0.0–1.0) for the input area in the main dialog. */
        public static final double DEFAULT_DIVIDER_LOCATION = 0.2;

        private List<TabModel> tabs;
        private double dividerLocation;
        private Map<String, Map<String, String>> processorSettings;

        /** No-arg constructor for Jackson; also used when default load fails. */
        public Data() {
            this.tabs = new ArrayList<>();
            this.dividerLocation = DEFAULT_DIVIDER_LOCATION;
            this.processorSettings = new HashMap<>();
        }

        /**
         * Creates data with the given tabs and divider. Divider is clamped to 0.0–1.0. Processor
         * settings are empty.
         */
        public Data(List<TabModel> tabs, double dividerLocation) {
            this.tabs = new ArrayList<>(tabs);
            this.dividerLocation =
                    dividerLocation >= 0.0 && dividerLocation <= 1.0
                            ? dividerLocation
                            : DEFAULT_DIVIDER_LOCATION;
            this.processorSettings = new HashMap<>();
        }

        void validateDividerLocation() {
            if (dividerLocation < 0.0 || dividerLocation > 1.0) {
                this.dividerLocation = DEFAULT_DIVIDER_LOCATION;
            }
        }

        @Override
        public String getProcessorSetting(String processorId, String key) {
            if (processorSettings == null) return null;
            Map<String, String> perProcessor = processorSettings.get(processorId);
            return perProcessor != null ? perProcessor.get(key) : null;
        }

        @Override
        public void setProcessorSetting(String processorId, String key, String value) {
            if (processorSettings == null) {
                processorSettings = new HashMap<>();
            }
            processorSettings
                    .computeIfAbsent(processorId, k -> new HashMap<>())
                    .put(key, value);
        }

        @Override
        public void clearProcessorSetting(String processorId, String key) {
            if (processorSettings == null) return;
            Map<String, String> perProcessor = processorSettings.get(processorId);
            if (perProcessor != null) {
                perProcessor.remove(key);
                if (perProcessor.isEmpty()) {
                    processorSettings.remove(processorId);
                }
            }
        }

        public List<TabModel> getTabs() {
            return tabs != null ? new ArrayList<>(tabs) : new ArrayList<>();
        }

        public void setTabs(List<TabModel> tabs) {
            this.tabs = tabs != null ? new ArrayList<>(tabs) : new ArrayList<>();
        }

        public double getDividerLocation() {
            return dividerLocation;
        }

        public void setDividerLocation(double dividerLocation) {
            this.dividerLocation =
                    dividerLocation >= 0.0 && dividerLocation <= 1.0
                            ? dividerLocation
                            : DEFAULT_DIVIDER_LOCATION;
        }

        public Map<String, Map<String, String>> getProcessorSettings() {
            if (processorSettings == null) {
                return new HashMap<>();
            }
            Map<String, Map<String, String>> copy = new HashMap<>();
            for (Map.Entry<String, Map<String, String>> e : processorSettings.entrySet()) {
                copy.put(e.getKey(), new HashMap<>(e.getValue()));
            }
            return copy;
        }

        public void setProcessorSettings(Map<String, Map<String, String>> processorSettings) {
            this.processorSettings =
                    processorSettings != null ? new HashMap<>(processorSettings) : new HashMap<>();
        }
    }
}
