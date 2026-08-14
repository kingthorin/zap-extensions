/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.addon.commonlib.http.ComparableResponse;

public class HttpParameterPollutionScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    private static final int PLUGIN_ID = 20014;

    @FunctionalInterface
    private interface CheckMethod {
        boolean perform(HttpMessage msg, NameValuePair param, String canaryA, String canaryB)
                throws IOException;
    }

    enum CheckFamily {
        SAME_LOCATION_DUPLICATE(1),
        QUERY_VS_FORM(2),
        COOKIE_VS_QUERY(3),
        COOKIE_VS_FORM(4),
        QUERY_VS_STRUCTURED(5);

        final int postfix;

        CheckFamily(int postfix) {
            this.postfix = postfix;
        }

        String getAlertRef() {
            return PLUGIN_ID + "-" + postfix;
        }
    }

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2025_A05_INJECTION,
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A01_INJECTION,
                                CommonAlertTag.WSTG_V42_INPV_04_PARAM_POLLUTION));
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private static final Logger LOGGER = LogManager.getLogger(HttpParameterPollutionScanRule.class);

    private static final int CONFIRM_COUNT = 2;
    private static final float DISSIMILARITY_HIGH = 0.5f;
    private static final float DISSIMILARITY_MEDIUM = 0.4f;
    private static final float DISSIMILARITY_LOW = 0.3f;

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.hpp.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.hpp.desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanbeta.hpp.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanbeta.hpp.refs");
    }

    @Override
    public void scan(HttpMessage msg, NameValuePair param) {
        try {
            if (msg == null || param == null || param.getName() == null) {
                return;
            }

            int paramType = param.getType();
            Set<CheckFamily> enabledFamilies = getEnabledCheckFamilies(paramType);

            if (enabledFamilies.isEmpty()) {
                LOGGER.debug("No check families enabled for param type: {}", paramType);
                return;
            }

            for (CheckFamily family : enabledFamilies) {
                if (isStop()) {
                    return;
                }
                runCheckFamily(msg, param, family);
            }
        } catch (Exception e) {
            LOGGER.error("Error during HPP scan of param: {}", param.getName(), e);
        }
    }

    private Set<CheckFamily> getEnabledCheckFamilies(int paramType) {
        Set<CheckFamily> families = new LinkedHashSet<>();
        AttackStrength strength = this.getAttackStrength();
        boolean cookiesEnabled =
                (getParent().getScannerParam().getTargetParamsInjectable()
                                & ScannerParam.TARGET_COOKIE)
                        != 0;

        if (paramType == NameValuePair.TYPE_QUERY_STRING) {
            families.add(CheckFamily.SAME_LOCATION_DUPLICATE);

            if (strength.compareTo(AttackStrength.MEDIUM) >= 0) {
                families.add(CheckFamily.QUERY_VS_FORM);
            }

            if (strength.compareTo(AttackStrength.HIGH) >= 0 && cookiesEnabled) {
                families.add(CheckFamily.COOKIE_VS_QUERY);
            }
        } else if (paramType == NameValuePair.TYPE_POST_DATA
                || paramType == NameValuePair.TYPE_MULTIPART_DATA_PARAM) {
            families.add(CheckFamily.SAME_LOCATION_DUPLICATE);

            if (strength.compareTo(AttackStrength.HIGH) >= 0 && cookiesEnabled) {
                families.add(CheckFamily.COOKIE_VS_FORM);
            }
        } else if (paramType == NameValuePair.TYPE_COOKIE
                && strength.compareTo(AttackStrength.HIGH) >= 0) {
            // Cookie as source: test if it affects query or form when injected elsewhere
            families.add(CheckFamily.COOKIE_VS_QUERY);
            families.add(CheckFamily.COOKIE_VS_FORM);
        }

        if (paramType == NameValuePair.TYPE_JSON) {
            if (strength.compareTo(AttackStrength.MEDIUM) >= 0) {
                families.add(CheckFamily.QUERY_VS_STRUCTURED);
            }
        }

        return families;
    }

    private CheckMethod getCheckMethod(CheckFamily family) {
        return switch (family) {
            case SAME_LOCATION_DUPLICATE -> this::checkSameLocationDuplicate;
            case QUERY_VS_FORM -> this::checkQueryVsForm;
            case COOKIE_VS_QUERY -> this::checkCookieVsQuery;
            case COOKIE_VS_FORM -> this::checkCookieVsForm;
            case QUERY_VS_STRUCTURED -> this::checkQueryVsStructured;
        };
    }

    private void runCheckFamily(HttpMessage msg, NameValuePair param, CheckFamily family) {
        CheckMethod check = getCheckMethod(family);
        for (int attempt = 0; attempt < CONFIRM_COUNT && !isStop(); attempt++) {
            String canaryA = generateContextualCanary(param);
            String canaryB = generateContextualCanary(param);

            try {
                if (check.perform(msg, param, canaryA, canaryB)) {
                    if (attempt == CONFIRM_COUNT - 1) {
                        createBaseAlert(family, canaryA, canaryB)
                                .setParam(param.getName())
                                .setMessage(msg)
                                .raise();
                    }
                } else {
                    return;
                }
            } catch (Exception e) {
                LOGGER.debug(
                        "Error running check family {} for param {}: {}",
                        family.getAlertRef(),
                        param.getName(),
                        e.getMessage());
                return;
            }
        }
    }

    private boolean checkSameLocationDuplicate(
            HttpMessage msg, NameValuePair param, String canaryA, String canaryB)
            throws IOException {
        int paramType = param.getType();
        if (paramType != NameValuePair.TYPE_QUERY_STRING
                && paramType != NameValuePair.TYPE_POST_DATA) {
            return false;
        }

        HttpMessage r1 = getNewMsg();
        ComparableResponse cr1 = sendAndCompare(r1, param.getValue(), "baseline");

        // Get a second baseline to tune heuristics against dynamic content
        HttpMessage r1b = getNewMsg();
        ComparableResponse cr1b = sendAndCompare(r1b, param.getValue(), "baseline-2");

        HttpMessage r2 = getNewMsg();
        setParameter(r2, param.getName(), canaryA);
        ComparableResponse cr2 = sendAndCompare(r2, canaryA, "single-canary");

        HttpMessage r3 = getNewMsg();
        addDuplicateParameter(r3, param, canaryA);
        ComparableResponse cr3 = sendAndCompare(r3, canaryA, "duplicate");

        cr1.tuneHeuristicsWithResponse(cr1b);

        return isImpedanceMismatch(cr1, cr2, cr3);
    }

    private boolean checkQueryVsForm(
            HttpMessage msg, NameValuePair param, String canaryA, String canaryB)
            throws IOException {
        int paramType = param.getType();
        if (paramType == NameValuePair.TYPE_QUERY_STRING) {
            return testCrossLocation(msg, param, NameValuePair.TYPE_POST_DATA, canaryA, canaryB);
        } else if (paramType == NameValuePair.TYPE_POST_DATA) {
            return testCrossLocation(msg, param, NameValuePair.TYPE_QUERY_STRING, canaryA, canaryB);
        }
        return false;
    }

    private boolean checkCookieVsQuery(
            HttpMessage msg, NameValuePair param, String canaryA, String canaryB)
            throws IOException {
        int paramType = param.getType();
        if (paramType == NameValuePair.TYPE_COOKIE) {
            return testCrossLocation(msg, param, NameValuePair.TYPE_QUERY_STRING, canaryA, canaryB);
        } else if (paramType == NameValuePair.TYPE_QUERY_STRING) {
            return testCrossLocation(msg, param, NameValuePair.TYPE_COOKIE, canaryA, canaryB);
        }
        return false;
    }

    private boolean checkCookieVsForm(
            HttpMessage msg, NameValuePair param, String canaryA, String canaryB)
            throws IOException {
        int paramType = param.getType();
        if (paramType == NameValuePair.TYPE_COOKIE) {
            return testCrossLocation(msg, param, NameValuePair.TYPE_POST_DATA, canaryA, canaryB);
        } else if (paramType == NameValuePair.TYPE_POST_DATA) {
            return testCrossLocation(msg, param, NameValuePair.TYPE_COOKIE, canaryA, canaryB);
        }
        return false;
    }

    private boolean checkQueryVsStructured(
            HttpMessage msg, NameValuePair param, String canaryA, String canaryB)
            throws IOException {
        int paramType = param.getType();
        if (paramType == NameValuePair.TYPE_QUERY_STRING) {
            // Query param exists: TODO inject canary into JSON body (requires JSON parsing support)
            return false;
        } else if (paramType == NameValuePair.TYPE_JSON) {
            // JSON param exists: test if injecting into query string causes impedance mismatch
            HttpMessage r1 = getNewMsg();
            ComparableResponse cr1 = sendAndCompare(r1, param.getValue(), "baseline");

            HttpMessage r1b = getNewMsg();
            ComparableResponse cr1b = sendAndCompare(r1b, param.getValue(), "baseline-2");

            HttpMessage r2 = getNewMsg();
            setParameter(r2, param.getName(), canaryA);
            ComparableResponse cr2 = sendAndCompare(r2, canaryA, "single-canary");

            HttpMessage r3 = getNewMsg();
            setParameter(r3, param.getName(), param.getValue());
            TreeSet<HtmlParameter> params = r3.getUrlParams();
            params.add(new HtmlParameter(HtmlParameter.Type.url, param.getName(), canaryA));
            r3.setGetParams(params);
            ComparableResponse cr3 = sendAndCompare(r3, canaryA, "query-inject");

            cr1.tuneHeuristicsWithResponse(cr1b);
            return isImpedanceMismatch(cr1, cr2, cr3);
        }
        return false;
    }

    private boolean testCrossLocation(
            HttpMessage msg, NameValuePair source, int targetType, String canaryA, String canaryB)
            throws IOException {
        HttpMessage r1 = getNewMsg();
        ComparableResponse cr1 = sendAndCompare(r1, source.getValue(), "baseline");

        HttpMessage r1b = getNewMsg();
        ComparableResponse cr1b = sendAndCompare(r1b, source.getValue(), "baseline-2");

        HttpMessage r2 = getNewMsg();
        setParameter(r2, source.getName(), canaryA);
        ComparableResponse cr2 = sendAndCompare(r2, canaryA, "single-location");

        HttpMessage r3 = getNewMsg();
        setParameter(r3, source.getName(), source.getValue());
        injectAtLocation(r3, source.getName(), canaryA, targetType);
        ComparableResponse cr3 = sendAndCompare(r3, canaryA, "cross-location");

        cr1.tuneHeuristicsWithResponse(cr1b);
        return isImpedanceMismatch(cr1, cr2, cr3);
    }

    private void addDuplicateParameter(HttpMessage msg, NameValuePair param, String canaryValue) {
        String name = param.getName();
        int paramType = param.getType();

        if (paramType == NameValuePair.TYPE_QUERY_STRING) {
            TreeSet<HtmlParameter> params = msg.getUrlParams();
            params.add(new HtmlParameter(HtmlParameter.Type.url, name, canaryValue));
            msg.setGetParams(params);
        } else if (paramType == NameValuePair.TYPE_POST_DATA) {
            TreeSet<HtmlParameter> params = msg.getFormParams();
            params.add(new HtmlParameter(HtmlParameter.Type.form, name, canaryValue));
            msg.setFormParams(params);
        } else if (paramType == NameValuePair.TYPE_MULTIPART_DATA_PARAM) {
            setParameter(msg, name, canaryValue);
        }
    }

    private void injectAtLocation(
            HttpMessage msg, String paramName, String canaryValue, int targetType) {
        if (targetType == NameValuePair.TYPE_QUERY_STRING) {
            TreeSet<HtmlParameter> params = msg.getUrlParams();
            params.add(new HtmlParameter(HtmlParameter.Type.url, paramName, canaryValue));
            msg.setGetParams(params);
        } else if (targetType == NameValuePair.TYPE_POST_DATA) {
            TreeSet<HtmlParameter> params = msg.getFormParams();
            params.add(new HtmlParameter(HtmlParameter.Type.form, paramName, canaryValue));
            msg.setFormParams(params);
        } else if (targetType == NameValuePair.TYPE_COOKIE) {
            try {
                TreeSet<HtmlParameter> cookies = msg.getCookieParams();
                cookies.add(new HtmlParameter(HtmlParameter.Type.cookie, paramName, canaryValue));
                msg.setCookieParams(cookies);
            } catch (Exception e) {
                LOGGER.debug("Failed to inject cookie parameter: {}", e.getMessage());
            }
        } else if (targetType == NameValuePair.TYPE_MULTIPART_DATA_PARAM) {
            try {
                setParameter(msg, paramName, canaryValue);
            } catch (Exception e) {
                LOGGER.debug("Failed to inject multipart parameter: {}", e.getMessage());
            }
        }
    }

    private ComparableResponse sendAndCompare(HttpMessage msg, String valueSent, String label) {
        try {
            sendAndReceive(msg);
            return new ComparableResponse(msg, valueSent);
        } catch (IOException e) {
            LOGGER.debug("Error sending request for {}: {}", label, e.getMessage());
            return null;
        }
    }

    private boolean isImpedanceMismatch(
            ComparableResponse cr1, ComparableResponse cr2, ComparableResponse cr3) {
        if (cr1 == null || cr2 == null || cr3 == null) {
            return false;
        }

        // Check if baseline itself is too volatile (skip if dynamic content)
        float baselineVolatility = 1.0f - cr1.compareWith(cr2);
        if (baselineVolatility > DISSIMILARITY_MEDIUM) {
            LOGGER.debug("Baseline too volatile, skipping check");
            return false;
        }

        // Check if R3 is an error response while R1/R2 are successful
        if (isErrorResponse(cr3) && !isErrorResponse(cr1) && !isErrorResponse(cr2)) {
            LOGGER.debug("R3 is error response while R1/R2 are successful, skipping");
            return false;
        }

        cr1.tuneHeuristicsWithResponse(cr2);

        float similarity1 = cr3.compareWith(cr1);
        float similarity2 = cr3.compareWith(cr2);

        float dissimilarity1 = 1.0f - similarity1;
        float dissimilarity2 = 1.0f - similarity2;

        AlertThreshold threshold = this.getAlertThreshold();
        float dissimilarityThreshold =
                threshold == AlertThreshold.HIGH
                        ? DISSIMILARITY_HIGH
                        : (threshold == AlertThreshold.MEDIUM
                                ? DISSIMILARITY_MEDIUM
                                : DISSIMILARITY_LOW);

        return dissimilarity1 >= dissimilarityThreshold && dissimilarity2 >= dissimilarityThreshold;
    }

    private boolean isErrorResponse(ComparableResponse response) {
        int statusCode = response.getStatusCode();
        if (statusCode >= 400) {
            return true;
        }
        String body = response.getBody().toLowerCase();
        return body.contains("error")
                || body.contains("invalid")
                || body.contains("not found")
                || body.contains("bad request")
                || body.contains("forbidden");
    }

    private Alert buildExampleAlert(CheckFamily family) {
        return createBaseAlert(family, "zap_12345678", "zap_87654321").build();
    }

    private AlertBuilder createBaseAlert(CheckFamily family, String canaryA, String canaryB) {
        String alertRef = family.getAlertRef();
        String description = Constant.messages.getString("ascanbeta.hpp." + alertRef + ".name");
        String otherInfo =
                Constant.messages.getString(
                        "ascanbeta.hpp.otherinfo", description, canaryA, canaryB);

        return newAlert()
                .setAlertRef(alertRef)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setOtherInfo(otherInfo);
    }

    private String generateCanary() {
        return "zap_" + UUID.randomUUID().toString().substring(0, 8);
    }

    private String generateContextualCanary(NameValuePair param) {
        ValueProvider provider = getValueProvider();
        if (provider == null) {
            return generateCanary();
        }

        try {
            String value =
                    provider.getValue(
                            getBaseMsg().getRequestHeader().getURI(),
                            getBaseMsg().getRequestHeader().getURI().toString(),
                            param.getName(),
                            null,
                            null,
                            null,
                            null);
            return value + "_zap_" + UUID.randomUUID().toString().substring(0, 4);
        } catch (Exception e) {
            LOGGER.debug(
                    "ValueProvider failed for param {}, falling back to UUID canary: {}",
                    param.getName(),
                    e.getMessage());
            return generateCanary();
        }
    }

    private ValueProvider getValueProvider() {
        try {
            ExtensionCommonlib extension =
                    org.parosproxy.paros.control.Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionCommonlib.class);
            if (extension == null) {
                return null;
            }
            return extension.getValueProvider();
        } catch (Exception e) {
            LOGGER.debug("Failed to get ValueProvider: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public int getRisk() {
        return Alert.RISK_INFO;
    }

    @Override
    public int getCweId() {
        return 20; // CWE-20: Improper Input Validation
    }

    @Override
    public int getWascId() {
        return 20; // WASC-20: Improper Input Handling
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                buildExampleAlert(CheckFamily.SAME_LOCATION_DUPLICATE),
                buildExampleAlert(CheckFamily.QUERY_VS_FORM),
                buildExampleAlert(CheckFamily.COOKIE_VS_QUERY),
                buildExampleAlert(CheckFamily.COOKIE_VS_FORM),
                buildExampleAlert(CheckFamily.QUERY_VS_STRUCTURED));
    }
}
