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
package org.zaproxy.zap.extension.scripts.diagnostics;

import java.util.List;
import java.util.Optional;

/** Engine-provided diagnostics from a completed script run. */
public interface ScriptDiagnosticSource {

    /**
     * {@code context}: full diagnostic text; {@code detailMessage}: single-line summary; unknown
     * indices are {@code -1}.
     */
    record RunFailureDiagnostic(
            String context,
            String detailMessage,
            int chainScriptOrder,
            int sourceStatementIndex,
            String elementType,
            String screenshotBase64) {}

    /** One stdout line from a completed run, attributed by the engine runner. */
    record RunOutput(
            String scriptName,
            int sourceStatementIndex,
            int ordinal,
            String elementType,
            String message) {}

    Optional<RunFailureDiagnostic> getLastRunFailure();

    List<RunOutput> getRunOutputs();

    void clearRunDiagnostics();
}
