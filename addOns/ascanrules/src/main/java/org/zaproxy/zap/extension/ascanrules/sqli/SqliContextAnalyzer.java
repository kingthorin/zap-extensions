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
package org.zaproxy.zap.extension.ascanrules.sqli;

import java.util.regex.Pattern;
import org.parosproxy.paros.network.HttpMessage;

/** Analyzes baseline response to infer parameter context (numeric, string, etc.). */
public class SqliContextAnalyzer {

    private static final Pattern NUMERIC_VALUE = Pattern.compile("^\\d+$");
    private static final int MIN_RESPONSE_SIZE = 100;

    /**
     * Analyzes the baseline response to detect parameter context hints.
     *
     * @param originalValue the un-injected parameter value
     * @param baselineMsg the HTTP message from the baseline request
     * @return ParameterContext with detection hints
     */
    public static ParameterContext analyze(String originalValue, HttpMessage baselineMsg) {
        String responseBody = baselineMsg.getResponseBody().toString();

        boolean isNumericContext = NUMERIC_VALUE.matcher(originalValue).matches();
        boolean isStringLiteralContext = !isNumericContext;
        boolean isLikeContext = false;
        boolean isOrderByContext = false;
        boolean isExpressionContext = false;
        boolean baselineContainsErrorSignature =
                DbErrorSignatures.identify(responseBody).isPresent();

        boolean originalValueInResponse = responseBody.contains(originalValue);
        float dynamicContentVariance =
                responseBody.length() < MIN_RESPONSE_SIZE
                        ? 0.8f
                        : (originalValueInResponse ? 0.3f : 0.6f);

        return new ParameterContext(
                isNumericContext,
                isStringLiteralContext,
                isLikeContext,
                isOrderByContext,
                isExpressionContext,
                baselineContainsErrorSignature,
                dynamicContentVariance);
    }
}
