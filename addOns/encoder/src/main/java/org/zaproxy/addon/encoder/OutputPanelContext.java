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

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Encapsulates state and operations for a single output panel instance. Settings hierarchy:
 * instance (in-memory) → processor override (persisted per processor) → legacy global (only when
 * already present in config, e.g. after upgrade from Options panel) → hard default. We never
 * persist "global"; only per-processor overrides. Clearing an override falls back to hard default
 * (or legacy global if it exists in config). Acts as bridge between UI (toolbar) and processors.
 * The dialog passes this context into {@link
 * org.zaproxy.addon.encoder.processors.EncodeDecodeProcessor#process(String, OutputPanelContext)}
 * so processors that support per-panel settings can read from it.
 */
public class OutputPanelContext {

    /** Setting key for Base64 charset (string). */
    public static final String KEY_BASE64_CHARSET = "base64.charset";

    /** Setting key for Base64 break lines (boolean). */
    public static final String KEY_BASE64_BREAK_LINES = "base64.breakLines";

    /** Setting key for hashers output lowercase (boolean). */
    public static final String KEY_HASHERS_LOWERCASE = "hashers.lowercase";

    private final OutputPanelModel panelModel;
    private final ProcessorSettingStore processorStore;
    private final EncodeDecodeOptions globalOptions;
    private final Runnable reprocessCallback;
    private final Consumer<String> onProcessorSettingPersisted;
    private final Map<String, String> instanceSettings = new HashMap<>();

    /**
     * Constructor with optional callback when a processor setting is persisted. Use when the dialog
     * needs to refresh other panels' toolbars for the same processor.
     *
     * @param panelModel the output panel model
     * @param processorStore store for per-processor overrides (e.g. {@link EncoderConfig.Data})
     * @param globalOptions legacy global options (for base64 charset, break lines, hashers lowercase)
     * @param reprocessCallback run when a setting changes
     * @param onProcessorSettingPersisted optional callback when an override is persisted
     */
    public OutputPanelContext(
            OutputPanelModel panelModel,
            ProcessorSettingStore processorStore,
            EncodeDecodeOptions globalOptions,
            Runnable reprocessCallback,
            Consumer<String> onProcessorSettingPersisted) {
        this.panelModel = panelModel;
        this.processorStore = processorStore;
        this.globalOptions = globalOptions;
        this.reprocessCallback = reprocessCallback;
        this.onProcessorSettingPersisted = onProcessorSettingPersisted;
    }

    /** Constructor without persist callback (e.g. tests). */
    public OutputPanelContext(
            OutputPanelModel panelModel,
            ProcessorSettingStore processorStore,
            EncodeDecodeOptions globalOptions,
            Runnable reprocessCallback) {
        this(panelModel, processorStore, globalOptions, reprocessCallback, null);
    }

    public OutputPanelModel getPanelModel() {
        return panelModel;
    }

    /**
     * Gets a string setting. Lookup order: instance → processor override → legacy global (if
     * present in config) → hard default.
     *
     * @param key setting key (e.g. {@link #KEY_BASE64_CHARSET})
     * @return the value, never null for known keys
     */
    public String getString(String key) {
        String value = instanceSettings.get(key);
        if (value != null) return value;
        value = getProcessorOverride(key);
        if (value != null) return value;
        value = getGlobalString(key);
        if (value != null) return value;
        return getDefaultString(key);
    }

    /**
     * Gets a boolean setting. Lookup order: instance → processor override → legacy global (if
     * present in config) → hard default.
     *
     * @param key setting key (e.g. {@link #KEY_BASE64_BREAK_LINES})
     */
    public boolean getBoolean(String key) {
        String value = instanceSettings.get(key);
        if (value != null) return Boolean.parseBoolean(value);
        value = getProcessorOverride(key);
        if (value != null) return Boolean.parseBoolean(value);
        Boolean global = getGlobalBoolean(key);
        if (global != null) return global;
        return getDefaultBoolean(key);
    }

    /**
     * Sets a string setting. Updates instance and, if different from hard default, persists a
     * processor-specific override; otherwise clears any override. Then calls {@link
     * #requestReprocess()}.
     */
    public void setSetting(String key, String value) {
        instanceSettings.put(key, value);
        persistProcessorOverrideIfNeeded(key, value);
        requestReprocess();
    }

    /**
     * Sets a boolean setting. Updates instance and, if different from hard default, persists a
     * processor-specific override; otherwise clears any override. Then calls {@link
     * #requestReprocess()}.
     */
    public void setSetting(String key, boolean value) {
        String str = String.valueOf(value);
        instanceSettings.put(key, str);
        persistProcessorOverrideIfNeeded(key, str);
        requestReprocess();
    }

    /** Asks the dialog to reprocess this panel's output. */
    public void requestReprocess() {
        if (reprocessCallback != null) {
            reprocessCallback.run();
        }
    }

    private String getProcessorOverride(String key) {
        if (processorStore == null) return null;
        return processorStore.getProcessorSetting(panelModel.getProcessorId(), key);
    }

    /**
     * Returns legacy global value only when it was explicitly set in config (e.g. upgrade from
     * Options panel). If it equals the hard default, return null so we fall through to hard
     * default.
     */
    private String getGlobalString(String key) {
        if (globalOptions == null) return null;
        if (KEY_BASE64_CHARSET.equals(key)) {
            String v = globalOptions.getBase64Charset();
            return v != null && !v.equals(EncodeDecodeOptions.DEFAULT_CHARSET) ? v : null;
        }
        return null;
    }

    private Boolean getGlobalBoolean(String key) {
        if (globalOptions == null) return null;
        if (KEY_BASE64_BREAK_LINES.equals(key)) {
            boolean v = globalOptions.isBase64DoBreakLines();
            return v != EncodeDecodeOptions.DEFAULT_DO_BREAK_LINES ? v : null;
        }
        if (KEY_HASHERS_LOWERCASE.equals(key)) {
            boolean v = globalOptions.isHashersLowerCase();
            return v != EncodeDecodeOptions.DEFAULT_DO_LOWERCASE ? v : null;
        }
        return null;
    }

    private String getDefaultString(String key) {
        if (KEY_BASE64_CHARSET.equals(key)) return EncodeDecodeOptions.DEFAULT_CHARSET;
        return "";
    }

    private boolean getDefaultBoolean(String key) {
        if (KEY_BASE64_BREAK_LINES.equals(key)) return EncodeDecodeOptions.DEFAULT_DO_BREAK_LINES;
        if (KEY_HASHERS_LOWERCASE.equals(key)) return EncodeDecodeOptions.DEFAULT_DO_LOWERCASE;
        return false;
    }

    /** Returns the default value for the key as a string (for persistence comparison). */
    private String getDefaultValueAsString(String key) {
        if (KEY_BASE64_CHARSET.equals(key)) return getDefaultString(key);
        if (KEY_BASE64_BREAK_LINES.equals(key) || KEY_HASHERS_LOWERCASE.equals(key)) {
            return String.valueOf(getDefaultBoolean(key));
        }
        return null;
    }

    private void persistProcessorOverrideIfNeeded(String key, String value) {
        if (processorStore == null) return;
        String defaultStr = getDefaultValueAsString(key);
        boolean isDefault = defaultStr != null && defaultStr.equals(value);
        String processorId = panelModel.getProcessorId();
        if (isDefault) {
            processorStore.clearProcessorSetting(processorId, key);
        } else {
            processorStore.setProcessorSetting(processorId, key, value);
        }
        if (onProcessorSettingPersisted != null) {
            onProcessorSettingPersisted.accept(processorId);
        }
    }
}
