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

/**
 * Store for per-processor toolbar settings (e.g. Base64 charset, hashers lowercase). Used by
 * {@link OutputPanelContext} to read and persist overrides. May be backed by {@link
 * EncoderConfig.Data} or another implementation.
 */
public interface ProcessorSettingStore {

    /**
     * Gets a processor-specific override.
     *
     * @param processorId e.g. encoder.predefined.base64encode
     * @param key setting key (e.g. base64.charset, base64.breakLines)
     * @return the value if set, or null
     */
    String getProcessorSetting(String processorId, String key);

    /**
     * Sets a processor-specific override.
     *
     * @param processorId e.g. encoder.predefined.base64encode
     * @param key setting key
     * @param value value to store (booleans as "true"/"false")
     */
    void setProcessorSetting(String processorId, String key, String value);

    /**
     * Removes a processor-specific override.
     *
     * @param processorId e.g. encoder.predefined.base64encode
     * @param key setting key
     */
    void clearProcessorSetting(String processorId, String key);
}
