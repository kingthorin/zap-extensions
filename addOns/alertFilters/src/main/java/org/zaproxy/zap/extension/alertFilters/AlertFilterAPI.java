/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiException.Type;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.ApiUtils;
import org.zaproxy.zap.utils.XMLStringUtil;

/** The API for manipulating {@link AlertFilter alert filters}. */
public class AlertFilterAPI extends ApiImplementor {

    private static final Logger LOGGER = LogManager.getLogger(AlertFilterAPI.class);

    private static final String PREFIX = "alertFilter";

    private static final String VIEW_ALERT_FILTER_LIST = "alertFilterList";
    private static final String VIEW_GLOBAL_ALERT_FILTER_LIST = "globalAlertFilterList";

    private static final String ACTION_ADD_ALERT_FILTER = "addAlertFilter";
    private static final String ACTION_REMOVE_ALERT_FILTER = "removeAlertFilter";
    private static final String ACTION_ADD_GLOBAL_ALERT_FILTER = "addGlobalAlertFilter";
    private static final String ACTION_REMOVE_GLOBAL_ALERT_FILTER = "removeGlobalAlertFilter";
    private static final String ACTION_APPLY_ALL = "applyAll";
    private static final String ACTION_APPLY_CONTEXT = "applyContext";
    private static final String ACTION_APPLY_GLOBAL = "applyGlobal";
    private static final String ACTION_TEST_ALL = "testAll";
    private static final String ACTION_TEST_CONTEXT = "testContext";
    private static final String ACTION_TEST_GLOBAL = "testGlobal";

    private static final String PARAM_CONTEXT_ID = "contextId";
    private static final String PARAM_RULE_ID = "ruleId";
    private static final String PARAM_NEW_LEVEL = "newLevel";
    private static final String PARAM_URL = "url";
    private static final String PARAM_URL_IS_REGEX = "urlIsRegex";
    private static final String PARAM_PARAMETER = "parameter";
    private static final String PARAM_PARAMETER_IS_REGEX = "parameterIsRegex";
    private static final String PARAM_ATTACK = "attack";
    private static final String PARAM_ATTACK_IS_REGEX = "attackIsRegex";
    private static final String PARAM_EVIDENCE = "evidence";
    private static final String PARAM_EVIDENCE_IS_REGEX = "evidenceIsRegex";
    private static final String PARAM_METHODS = "methods";
    private static final String PARAM_ENABLED = "enabled";

    private ExtensionAlertFilters extension;

    /** Provided only for API client generator usage. */
    public AlertFilterAPI() {
        this(null);
    }

    public AlertFilterAPI(ExtensionAlertFilters extension) {
        super();
        this.extension = extension;

        this.addApiView(new ApiView(VIEW_ALERT_FILTER_LIST, new String[] {PARAM_CONTEXT_ID}));
        this.addApiView(new ApiView(VIEW_GLOBAL_ALERT_FILTER_LIST));

        this.addApiAction(
                new ApiAction(
                        ACTION_ADD_ALERT_FILTER,
                        new String[] {PARAM_CONTEXT_ID, PARAM_RULE_ID, PARAM_NEW_LEVEL},
                        new String[] {
                            PARAM_URL,
                            PARAM_URL_IS_REGEX,
                            PARAM_PARAMETER,
                            PARAM_ENABLED,
                            PARAM_PARAMETER_IS_REGEX,
                            PARAM_ATTACK,
                            PARAM_ATTACK_IS_REGEX,
                            PARAM_EVIDENCE,
                            PARAM_EVIDENCE_IS_REGEX,
                            PARAM_METHODS,
                        }));
        this.addApiAction(
                new ApiAction(
                        ACTION_REMOVE_ALERT_FILTER,
                        new String[] {PARAM_CONTEXT_ID, PARAM_RULE_ID, PARAM_NEW_LEVEL},
                        new String[] {
                            PARAM_URL,
                            PARAM_URL_IS_REGEX,
                            PARAM_PARAMETER,
                            PARAM_ENABLED,
                            PARAM_PARAMETER_IS_REGEX,
                            PARAM_ATTACK,
                            PARAM_ATTACK_IS_REGEX,
                            PARAM_EVIDENCE,
                            PARAM_EVIDENCE_IS_REGEX,
                            PARAM_METHODS,
                        }));
        this.addApiAction(
                new ApiAction(
                        ACTION_ADD_GLOBAL_ALERT_FILTER,
                        new String[] {PARAM_RULE_ID, PARAM_NEW_LEVEL},
                        new String[] {
                            PARAM_URL,
                            PARAM_URL_IS_REGEX,
                            PARAM_PARAMETER,
                            PARAM_ENABLED,
                            PARAM_PARAMETER_IS_REGEX,
                            PARAM_ATTACK,
                            PARAM_ATTACK_IS_REGEX,
                            PARAM_EVIDENCE,
                            PARAM_EVIDENCE_IS_REGEX,
                            PARAM_METHODS,
                        }));
        this.addApiAction(
                new ApiAction(
                        ACTION_REMOVE_GLOBAL_ALERT_FILTER,
                        new String[] {PARAM_RULE_ID, PARAM_NEW_LEVEL},
                        new String[] {
                            PARAM_URL,
                            PARAM_URL_IS_REGEX,
                            PARAM_PARAMETER,
                            PARAM_ENABLED,
                            PARAM_PARAMETER_IS_REGEX,
                            PARAM_ATTACK,
                            PARAM_ATTACK_IS_REGEX,
                            PARAM_EVIDENCE,
                            PARAM_EVIDENCE_IS_REGEX,
                            PARAM_METHODS,
                        }));
        this.addApiAction(new ApiAction(ACTION_APPLY_ALL));
        this.addApiAction(new ApiAction(ACTION_APPLY_CONTEXT));
        this.addApiAction(new ApiAction(ACTION_APPLY_GLOBAL));
        this.addApiAction(new ApiAction(ACTION_TEST_ALL));
        this.addApiAction(new ApiAction(ACTION_TEST_CONTEXT));
        this.addApiAction(new ApiAction(ACTION_TEST_GLOBAL));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    protected String getI18nPrefix() {
        return ExtensionAlertFilters.PREFIX;
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        LOGGER.debug("handleApiView {} {}", name, params);
        Context context;

        switch (name) {
            case VIEW_ALERT_FILTER_LIST:
                ApiResponseList listResponse = new ApiResponseList(name);
                context = ApiUtils.getContextByParamId(params, PARAM_CONTEXT_ID);
                List<AlertFilter> afs =
                        extension.getContextAlertFilterManager(context.getId()).getAlertFilters();

                for (AlertFilter af : afs) {
                    listResponse.addItem(buildResponseFromAlertFilter(af, true));
                }
                return listResponse;

            case VIEW_GLOBAL_ALERT_FILTER_LIST:
                ApiResponseList globalListResponse = new ApiResponseList(name);
                Set<AlertFilter> gafs = extension.getParam().getGlobalAlertFilters();

                for (AlertFilter af : gafs) {
                    globalListResponse.addItem(buildResponseFromAlertFilter(af, false));
                }
                return globalListResponse;

            default:
                throw new ApiException(ApiException.Type.BAD_VIEW);
        }
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        LOGGER.debug("handleApiAction {} {}", name, params);

        AlertFilter af;
        Context context;
        switch (name) {
            case ACTION_ADD_ALERT_FILTER:
                context = ApiUtils.getContextByParamId(params, PARAM_CONTEXT_ID);
                af =
                        new AlertFilter(
                                context.getId(),
                                params.getString(PARAM_RULE_ID),
                                ApiUtils.getIntParam(params, PARAM_NEW_LEVEL),
                                ApiUtils.getOptionalStringParam(params, PARAM_URL),
                                getParam(params, PARAM_URL_IS_REGEX, false),
                                ApiUtils.getOptionalStringParam(params, PARAM_PARAMETER),
                                getParam(params, PARAM_PARAMETER_IS_REGEX, false),
                                ApiUtils.getOptionalStringParam(params, PARAM_ATTACK),
                                getParam(params, PARAM_ATTACK_IS_REGEX, false),
                                ApiUtils.getOptionalStringParam(params, PARAM_EVIDENCE),
                                getParam(params, PARAM_EVIDENCE_IS_REGEX, false),
                                getMethods(params),
                                getParam(params, PARAM_ENABLED, true));

                // TODO more validation, esp url!
                extension.getContextAlertFilterManager(context.getId()).addAlertFilter(af);
                return ApiResponseElement.OK;
            case ACTION_REMOVE_ALERT_FILTER:
                context = ApiUtils.getContextByParamId(params, PARAM_CONTEXT_ID);
                af =
                        new AlertFilter(
                                context.getId(),
                                params.getString(PARAM_RULE_ID),
                                ApiUtils.getIntParam(params, PARAM_NEW_LEVEL),
                                ApiUtils.getOptionalStringParam(params, PARAM_URL),
                                getParam(params, PARAM_URL_IS_REGEX, false),
                                ApiUtils.getOptionalStringParam(params, PARAM_PARAMETER),
                                getParam(params, PARAM_PARAMETER_IS_REGEX, false),
                                ApiUtils.getOptionalStringParam(params, PARAM_ATTACK),
                                getParam(params, PARAM_ATTACK_IS_REGEX, false),
                                ApiUtils.getOptionalStringParam(params, PARAM_EVIDENCE),
                                getParam(params, PARAM_EVIDENCE_IS_REGEX, false),
                                getMethods(params),
                                getParam(params, PARAM_ENABLED, true));
                if (extension.getContextAlertFilterManager(context.getId()).removeAlertFilter(af)) {
                    return ApiResponseElement.OK;
                }

                return ApiResponseElement.FAIL;

            case ACTION_ADD_GLOBAL_ALERT_FILTER:
                af =
                        new AlertFilter(
                                -1,
                                params.getString(PARAM_RULE_ID),
                                ApiUtils.getIntParam(params, PARAM_NEW_LEVEL),
                                ApiUtils.getOptionalStringParam(params, PARAM_URL),
                                getParam(params, PARAM_URL_IS_REGEX, false),
                                ApiUtils.getOptionalStringParam(params, PARAM_PARAMETER),
                                getParam(params, PARAM_PARAMETER_IS_REGEX, false),
                                ApiUtils.getOptionalStringParam(params, PARAM_ATTACK),
                                getParam(params, PARAM_ATTACK_IS_REGEX, false),
                                ApiUtils.getOptionalStringParam(params, PARAM_EVIDENCE),
                                getParam(params, PARAM_EVIDENCE_IS_REGEX, false),
                                getMethods(params),
                                getParam(params, PARAM_ENABLED, true));

                // TODO more validation, esp url!
                if (extension.getParam().addAlertFilter(af)) {
                    try {
                        extension.getParam().getConfig().save();
                    } catch (ConfigurationException e) {
                        throw new ApiException(Type.INTERNAL_ERROR, e);
                    }
                    return ApiResponseElement.OK;
                }
                return ApiResponseElement.FAIL;

            case ACTION_REMOVE_GLOBAL_ALERT_FILTER:
                af =
                        new AlertFilter(
                                -1,
                                params.getString(PARAM_RULE_ID),
                                ApiUtils.getIntParam(params, PARAM_NEW_LEVEL),
                                ApiUtils.getOptionalStringParam(params, PARAM_URL),
                                getParam(params, PARAM_URL_IS_REGEX, false),
                                ApiUtils.getOptionalStringParam(params, PARAM_PARAMETER),
                                getParam(params, PARAM_PARAMETER_IS_REGEX, false),
                                ApiUtils.getOptionalStringParam(params, PARAM_ATTACK),
                                getParam(params, PARAM_ATTACK_IS_REGEX, false),
                                ApiUtils.getOptionalStringParam(params, PARAM_EVIDENCE),
                                getParam(params, PARAM_EVIDENCE_IS_REGEX, false),
                                getMethods(params),
                                getParam(params, PARAM_ENABLED, true));
                if (extension.getParam().removeFilter(af)) {
                    try {
                        extension.getParam().getConfig().save();
                    } catch (ConfigurationException e) {
                        throw new ApiException(Type.INTERNAL_ERROR, e);
                    }
                    return ApiResponseElement.OK;
                }
                return ApiResponseElement.FAIL;

            case ACTION_APPLY_ALL:
                Map<String, Integer> applyCountsMap = new HashMap<>(2, 1);
                applyCountsMap.put(ACTION_TEST_GLOBAL, applyGlobalAlertFilters(false));
                applyCountsMap.put(ACTION_TEST_CONTEXT, applyContextAlertFilters(false));
                return new ApiResponseSet<>(name, applyCountsMap);

            case ACTION_APPLY_CONTEXT:
                return new ApiResponseElement(
                        name, String.valueOf(applyContextAlertFilters(false)));

            case ACTION_APPLY_GLOBAL:
                return new ApiResponseElement(name, String.valueOf(applyGlobalAlertFilters(false)));

            case ACTION_TEST_ALL:
                Map<String, Integer> testCountsMap = new HashMap<>(2, 1);
                testCountsMap.put(ACTION_TEST_GLOBAL, applyGlobalAlertFilters(true));
                testCountsMap.put(ACTION_TEST_CONTEXT, applyContextAlertFilters(true));
                return new ApiResponseSet<>(name, testCountsMap);

            case ACTION_TEST_CONTEXT:
                return new ApiResponseElement(name, String.valueOf(applyContextAlertFilters(true)));

            case ACTION_TEST_GLOBAL:
                return new ApiResponseElement(name, String.valueOf(applyGlobalAlertFilters(true)));

            default:
                throw new ApiException(Type.BAD_ACTION);
        }
    }

    private static Set<String> getMethods(JSONObject params) {
        String value = ApiUtils.getOptionalStringParam(params, PARAM_METHODS);
        if (value == null) {
            return Set.of();
        }
        return Set.of(value.split(",", -1));
    }

    private int applyContextAlertFilters(boolean testOnly) {
        return Model.getSingleton().getSession().getContexts().stream()
                .map(
                        ctx ->
                                extension
                                        .getContextAlertFilterManager(ctx.getId())
                                        .getAlertFilters()
                                        .stream()
                                        .filter(AlertFilter::isEnabled)
                                        .map(f -> extension.applyAlertFilter(f, testOnly))
                                        .collect(Collectors.summingInt(Integer::intValue)))
                .collect(Collectors.summingInt(Integer::intValue));
    }

    private int applyGlobalAlertFilters(boolean testOnly) {
        return extension.getParam().getGlobalAlertFilters().stream()
                .filter(AlertFilter::isEnabled)
                .map(f -> extension.applyAlertFilter(f, testOnly))
                .collect(Collectors.summingInt(Integer::intValue));
    }

    /**
     * Builds the response describing an AlertFilter
     *
     * @param af the AlertFilter
     * @return the api response
     */
    private ApiResponse buildResponseFromAlertFilter(AlertFilter af, boolean includeContext) {
        Map<String, Object> fields = new HashMap<>();
        if (includeContext) {
            fields.put(PARAM_CONTEXT_ID, Integer.toString(af.getContextId()));
        }
        fields.put(PARAM_RULE_ID, af.getRuleId());
        fields.put(PARAM_NEW_LEVEL, Integer.toString(af.getNewRisk()));
        fields.put(PARAM_URL, af.getUrl());
        fields.put(PARAM_URL_IS_REGEX, Boolean.toString(af.isUrlRegex()));
        fields.put(PARAM_PARAMETER, af.getParameter());
        fields.put(PARAM_PARAMETER_IS_REGEX, Boolean.toString(af.isParameterRegex()));
        fields.put(PARAM_ATTACK, af.getAttack());
        fields.put(PARAM_ATTACK_IS_REGEX, Boolean.toString(af.isAttackRegex()));
        fields.put(PARAM_EVIDENCE, af.getEvidence());
        fields.put(PARAM_EVIDENCE_IS_REGEX, Boolean.toString(af.isEvidenceRegex()));
        fields.put(PARAM_METHODS, af.getMethods());
        fields.put(PARAM_ENABLED, Boolean.toString(af.isEnabled()));
        return new AlertFilterResponseSet<>("alertFilter", fields);
    }

    private static class AlertFilterResponseSet<T> extends ApiResponseSet<T> {

        AlertFilterResponseSet(String name, Map<String, T> values) {
            super(name, values);
        }

        @Override
        public void toXML(Document doc, Element parent) {
            parent.setAttribute("type", "set");
            for (Map.Entry<String, T> val : getValues().entrySet()) {
                Element el = doc.createElement(val.getKey());
                if ("methods".equals(val.getKey())) {
                    el.setAttribute("type", "list");
                    @SuppressWarnings("unchecked")
                    Set<String> methods = (Set<String>) val.getValue();
                    for (String method : methods) {
                        Element element = doc.createElement("method");
                        element.appendChild(
                                doc.createTextNode(XMLStringUtil.escapeControlChrs(method)));

                        el.appendChild(element);
                    }
                } else {
                    String textValue = val.getValue() == null ? "" : val.getValue().toString();
                    Text text = doc.createTextNode(XMLStringUtil.escapeControlChrs(textValue));
                    el.appendChild(text);
                }
                parent.appendChild(el);
            }
        }
    }
}
