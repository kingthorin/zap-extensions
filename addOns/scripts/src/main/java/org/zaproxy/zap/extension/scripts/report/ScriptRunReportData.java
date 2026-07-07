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
package org.zaproxy.zap.extension.scripts.report;

import java.util.List;

public final class ScriptRunReportData {

    private ScriptRunReportData() {}

    public record Diagnostics(List<Run> runs) {}

    public record Run(String created, String outcome, String summary, List<Script> scripts) {}

    public record Script(int order, String scriptName, String scriptType, List<Step> steps) {}

    public record Step(
            int sourceStepIndex,
            String line,
            List<Output> outputs,
            String screenshot,
            List<WebElement> webElements) {

        public Step(int sourceStepIndex, String line, List<Output> outputs) {
            this(sourceStepIndex, line, outputs, null, List.of());
        }
    }

    public record Output(String kind, String message) {}

    public record WebElement(
            Integer formIndex,
            String tagName,
            String attributeType,
            String attributeId,
            String attributeName,
            String attributeValue,
            String text,
            boolean displayed,
            boolean enabled,
            String selectorType,
            String selectorValue) {}
}
