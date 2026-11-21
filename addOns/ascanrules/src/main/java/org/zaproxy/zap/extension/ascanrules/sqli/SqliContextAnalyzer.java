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

import java.util.Locale;
import java.util.regex.Pattern;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascanrules.sqli.ParameterContext.ValueShape;

/** Analyzes baseline response to infer parameter context (numeric, string, etc.). */
public class SqliContextAnalyzer {

    private static final Pattern NUMERIC_VALUE = Pattern.compile("^\\d+$");
    private static final Pattern DATE_VALUE = Pattern.compile("^\\d{4}-\\d{1,2}-\\d{1,2}$");
    private static final Pattern IDENTIFIER_VALUE = Pattern.compile("^[A-Za-z_][A-Za-z0-9_.]*$");
    private static final Pattern SORT_DIRECTION_VALUE =
            Pattern.compile("(?i)^([A-Za-z_][A-Za-z0-9_.]*\\s+)?(asc|desc)$");
    private static final Pattern ORDER_BY_NAME =
            Pattern.compile(
                    "(?i)^(sort|order|orderby|order_by|sortby|sort_by|sortcol|sortcolumn|sort_column|sidx|ordercol|order_column)$");

    /**
     * Analyzes the parameter value and name for context hints.
     *
     * @param paramName the parameter name, or {@code null} if unknown
     * @param originalValue the un-injected parameter value
     * @param baselineMsg the HTTP message from the baseline request
     * @return ParameterContext with detection hints
     */
    public static ParameterContext analyze(
            String paramName, String originalValue, HttpMessage baselineMsg) {
        boolean isNumericContext = NUMERIC_VALUE.matcher(originalValue).matches();
        boolean isStringLiteralContext = !isNumericContext;
        ValueShape shape;
        if (isNumericContext) {
            shape = ValueShape.NUMERIC;
        } else if (DATE_VALUE.matcher(originalValue).matches()) {
            shape = ValueShape.DATE;
        } else if (IDENTIFIER_VALUE.matcher(originalValue).matches()) {
            shape = ValueShape.IDENTIFIER;
        } else {
            shape = ValueShape.TEXT;
        }
        boolean orderByHint =
                (paramName != null
                                && ORDER_BY_NAME
                                        .matcher(paramName.toLowerCase(Locale.ROOT))
                                        .matches())
                        || SORT_DIRECTION_VALUE.matcher(originalValue.trim()).matches();
        return new ParameterContext(isNumericContext, isStringLiteralContext, shape, orderByHint);
    }
}
