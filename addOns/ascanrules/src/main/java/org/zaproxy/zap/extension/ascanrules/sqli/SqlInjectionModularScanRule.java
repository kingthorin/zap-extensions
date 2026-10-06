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

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.AbstractPlugin.AlertBuilder;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Kb;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.ascanrules.CommonActiveScanRuleInfo;
import org.zaproxy.zap.extension.ascanrules.sqli.strategies.BooleanBasedDetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.strategies.ErrorBasedDetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.strategies.ExpressionBasedDetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.strategies.LoginBypassDetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.strategies.OrderByDetectionStrategy;
import org.zaproxy.zap.extension.ascanrules.sqli.strategies.UnionBasedDetectionStrategy;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * Modular SQL injection active scan rule, built to be a deliberately non-monolithic alternative to
 * the generic SQL injection rule (id 40018): each detection technique lives in its own {@link
 * DetectionStrategy} implementation instead of one large class mixing payload generation, response
 * comparison, and alerting together.
 *
 * <p>Temporary plugin id -- for local iteration only, not a real coordinated ZAP plugin id. Must
 * not be treated as final if this is ever proposed upstream.
 */
public class SqlInjectionModularScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo, ScanContext {

    /** Temporary id for local iteration -- see class javadoc. */
    public static final int PLUGIN_ID = 424242;

    private static final String MESSAGE_PREFIX = "ascanrules.sqlinjectionmodular.";
    private static final Logger LOGGER = LogManager.getLogger(SqlInjectionModularScanRule.class);

    /**
     * Version stamp on the presence records this rule writes to the knowledge base.
     *
     * <p>The knowledge base is a write-once set with no removal, so the stamp is the only way to
     * retire what an earlier format of this rule wrote: a record carrying any other stamp is
     * ignored, which is what {@link #isCurrentRecord(String)} is asked about on every read.
     */
    private static final String KB_RECORD_VERSION = "v1";

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.API_2023_API10_UNSAFE_CONSUMPTION,
                                CommonAlertTag.OWASP_2025_A05_INJECTION,
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A01_INJECTION,
                                CommonAlertTag.WSTG_V42_INPV_05_SQLI,
                                CommonAlertTag.HIPAA,
                                CommonAlertTag.PCI_DSS));
        alertTags.put(PolicyTag.API.getTag(), "");
        alertTags.put(PolicyTag.DEV_CICD.getTag(), "");
        alertTags.put(PolicyTag.DEV_STD.getTag(), "");
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_CICD.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    /**
     * One entry per detection technique, cheapest/most-common-first. {@link #scan} stops at the
     * first strategy that raises an alert. Strategies are added one at a time, each its own commit
     * with its own tests.
     */
    private final List<DetectionStrategy> strategies =
            List.of(
                    new ErrorBasedDetectionStrategy(),
                    new BooleanBasedDetectionStrategy(),
                    new ExpressionBasedDetectionStrategy(),
                    new OrderByDetectionStrategy(),
                    new UnionBasedDetectionStrategy(),
                    new LoginBypassDetectionStrategy());

    // Per-technique budgets, mirroring baseline rule 40018's ceilings (SqlInjectionScanRule
    // init(), lines 493-543): LOW = error + expression only; MEDIUM adds boolean/union (no order
    // by, no LIKE); HIGH adds order by; LIKE conditions are gated on HIGH by the boolean strategy.
    // Each strategy draws from its own reserved allocation, not a shared pool.
    //
    // The counts are one lower than 40018's, because the baseline is no longer in them:
    // scan() fetches one baseline per parameter and every technique diffs against that
    // one, so a technique's allocation is all probes. Before, each technique that
    // compared against a baseline paid the first request of its allocation for it
    // (BOOLEAN, EXPRESSION, ORDERBY, UNION, LOGINBYPASS). ERROR never did -- it used
    // the shared baseline from the start -- so it keeps 40018's numbers unchanged.
    private static final Map<String, int[]> TECHNIQUE_BUDGETS =
            Map.ofEntries(
                    Map.entry("ERROR", new int[] {4, 8, 16, 50}),
                    Map.entry("EXPRESSION", new int[] {3, 7, 15, 49}),
                    Map.entry("BOOLEAN", new int[] {0, 7, 19, 49}),
                    Map.entry("ORDERBY", new int[] {0, 0, 4, 49}),
                    Map.entry("UNION", new int[] {0, 4, 9, 49}),
                    Map.entry("LOGINBYPASS", new int[] {0, 5, 5, 5}));

    private String paramName;
    private String originalValue;
    private String currentTechnique = "";

    /**
     * Requests spent by each technique on the request last scanned, so the cost of a technique
     * order is measurable rather than argued about: the presence prior exists to spend the requests
     * of the techniques that will not find anything last.
     */
    private final Map<String, Integer> techniqueRequests = new HashMap<>();

    /**
     * Near-miss attribution, cleared with {@link #techniqueRequests}: how many times a probe
     * matched the baseline (the gate before any alert) and how many would-have-alerted
     * differentials the error-status guard suppressed. Reported by the metrics runner so a zero in
     * the false-positive column has something behind it.
     */
    private int baselineMatches;

    private int suppressedDifferentials;

    private Map<String, Integer> techniqueBudgets;
    private ParameterContext parameterContext;
    private HttpMessage cachedBaseline;
    private HttpMessage cachedControl;
    private HttpMessage cachedRepeat;

    @Override
    public void init() {
        initBudgets();
        // Per request rather than per parameter: scan() is called once for each parameter of a
        // request, and what each technique spent on the request as a whole is what the metrics
        // runner reports.
        techniqueRequests.clear();
        baselineMatches = 0;
        suppressedDifferentials = 0;
    }

    private void initBudgets() {
        int strengthIndex =
                switch (getAttackStrength()) {
                    case LOW -> 0;
                    case DEFAULT, MEDIUM -> 1;
                    case HIGH -> 2;
                    case INSANE -> 3;
                };

        techniqueBudgets = new HashMap<>();
        for (Map.Entry<String, int[]> entry : TECHNIQUE_BUDGETS.entrySet()) {
            techniqueBudgets.put(entry.getKey(), entry.getValue()[strengthIndex]);
        }
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 89;
    }

    @Override
    public int getWascId() {
        return 19;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        this.paramName = param;
        this.originalValue = value;

        URI uri = null;
        try {
            // One baseline per parameter, fetched here and shared by every technique: a technique
            // fetching its own copy only re-buys the same page, once per technique that compares
            // against a baseline. Fetched rather than reusing the base message because the base
            // message's response is whatever was last seen for that URL, not this request's own
            // response, and the diff-based techniques cannot tell a stale page from a payload
            // difference.
            cachedBaseline = getNewMsg();
            setParameter(cachedBaseline, param, value);
            super.sendAndReceive(cachedBaseline);
            parameterContext = SqliContextAnalyzer.analyze(value, cachedBaseline);
            // A replay is only meaningful for this parameter's own baseline; the previous
            // parameter's must not be reused.
            cachedRepeat = null;

            cachedControl = getNewMsg();
            setParameter(cachedControl, param, value + CONTROL_SUFFIX);
            super.sendAndReceive(cachedControl);

            // Scope of the path-level presence records below: this request's URI without its query,
            // which is what the knowledge base keys path-scoped entries on.
            uri = getBaseMsg().getRequestHeader().getURI();
        } catch (IOException e) {
            LOGGER.debug(
                    "Failed to initialize parameter context for parameter [{}]: {}",
                    param,
                    e.getMessage());
        }

        // 40018 reinitialises its per-technique counts for every parameter (SqlInjectionScanRule
        // scan(), "reinitialise the count for each type of request, for each parameter"), so a
        // multi-parameter request (page + username + password) starts each parameter with a full
        // budget rather than spending earlier parameters' requests from later ones' allowance.
        initBudgets();

        String[] techniqueNames = {
            "ERROR", "BOOLEAN", "EXPRESSION", "ORDERBY", "UNION", "LOGINBYPASS"
        };

        Integer[] order = techniqueOrder(uri, techniqueNames);

        for (int index : order) {
            if (isStop()) {
                return;
            }

            DetectionStrategy strategy = strategies.get(index);
            String technique = techniqueNames[index];
            setCurrentTechnique(technique);

            try {
                if (strategy.detect(this)) {
                    recordPresence(uri, technique);
                    return;
                }
            } catch (IOException e) {
                LOGGER.debug(
                        "{} failed for parameter [{}]: {}",
                        strategy.getClass().getSimpleName(),
                        param,
                        e.getMessage());
            }
        }
    }

    /**
     * Orders the techniques by how likely each is to find this injection: one that has already
     * found one for this parameter, or anywhere else on this host, goes first, and the rest fall
     * back to the static priors in {@link ParameterContext#estimateProbabilityFor(String)}.
     *
     * <p>Reorder only, never skip. Every technique still runs, so a record that has gone stale --
     * the injection was fixed, or the page was never injectable in the first place -- costs the
     * requests of the techniques that come after it finding nothing, and never an injection going
     * unreported.
     *
     * @param uri the request's URI, for the path-scoped records, or {@code null} if it has none
     * @param techniqueNames the technique names, in declared order
     * @return the indices of {@code techniqueNames}, most promising first
     */
    private Integer[] techniqueOrder(URI uri, String[] techniqueNames) {
        Integer[] order = new Integer[techniqueNames.length];
        float[] priors = new float[techniqueNames.length];
        for (int i = 0; i < order.length; i++) {
            order[i] = i;
            try {
                priors[i] = priorFor(uri, techniqueNames[i]);
            } catch (IOException e) {
                // A prior that cannot be read is no prior: the static one is the whole fallback.
                LOGGER.debug("Failed to read the injection presence prior: {}", e.getMessage());
                priors[i] = parameterContext.estimateProbabilityFor(techniqueNames[i]);
            }
        }
        // Arrays.sort is stable, so techniques the prior does not separate keep the declared order.
        Arrays.sort(order, (first, second) -> Float.compare(priors[second], priors[first]));
        return order;
    }

    private float priorFor(URI uri, String technique) throws IOException {
        if (hasPresenceRecord(uri, technique)) {
            return 1.0f;
        }
        return parameterContext.estimateProbabilityFor(technique);
    }

    /**
     * Tells whether the technique has already found an injection here, looking at this parameter on
     * this path first and then at the host as a whole.
     *
     * @param uri the request's URI, for the path-scoped records, or {@code null} if it has none
     * @param technique the technique name
     * @return {@code true} if a current presence record covers the technique
     * @throws IOException if a presence record could not be read
     */
    private boolean hasPresenceRecord(URI uri, String technique) throws IOException {
        Kb kb = getKb();
        if (uri != null && isCurrentRecord(kb.getString(uri, presenceKey(technique, paramName)))) {
            return true;
        }
        return isCurrentRecord(kb.getString(techniqueKey(technique)));
    }

    /**
     * Records that the technique found an injection, for this parameter on this path and for the
     * host as a whole, so the next parameter scanned here -- and the next page on this host --
     * starts with the technique that is known to work.
     *
     * @param uri the request's URI, for the path-scoped record, or {@code null} if it has none
     * @param technique the technique that found the injection
     * @throws IOException if the record could not be written
     */
    private void recordPresence(URI uri, String technique) throws IOException {
        Kb kb = getKb();
        if (uri != null) {
            kb.add(uri, presenceKey(technique, paramName), KB_RECORD_VERSION);
        }
        kb.add(techniqueKey(technique), KB_RECORD_VERSION);
    }

    private static String presenceKey(String technique, String param) {
        return "T=" + technique + "|p=" + param;
    }

    private static String techniqueKey(String technique) {
        return "T=" + technique;
    }

    static boolean isCurrentRecord(String record) {
        return KB_RECORD_VERSION.equals(record);
    }

    // -- ScanContext: thin delegation to the protected AbstractPlugin/AbstractAppParamPlugin
    // primitives that strategies (living in a different package) can't call directly. --

    @Override
    public HttpMessage getBaseMessage() {
        return getBaseMsg();
    }

    @Override
    public HttpMessage newMessage() {
        return getNewMsg();
    }

    @Override
    public void setParam(HttpMessage message, String value) {
        setParameter(message, paramName, value);
    }

    @Override
    public void sendAndReceive(HttpMessage message) throws IOException {
        super.sendAndReceive(message);
        techniqueRequests.merge(currentTechnique, 1, Integer::sum);
        if (techniqueBudgets != null && techniqueBudgets.containsKey(currentTechnique)) {
            int current = techniqueBudgets.get(currentTechnique);
            if (current > 0) {
                techniqueBudgets.put(currentTechnique, current - 1);
            }
        }
    }

    @Override
    public void setCurrentTechnique(String technique) {
        currentTechnique = technique;
    }

    @Override
    public boolean isStopped() {
        return isStop();
    }

    /**
     * Returns what each technique spent on the request that was scanned last, keyed by technique
     * name, summed over every parameter of that request. The baseline and control messages, fetched
     * once per parameter, are not charged to a technique and are not counted here.
     *
     * @return an unmodifiable map of technique name to the requests it sent
     */
    public Map<String, Integer> getTechniqueRequests() {
        return Map.copyOf(techniqueRequests);
    }

    @Override
    public AlertBuilder newAlert() {
        return super.newAlert();
    }

    @Override
    public String getParamName() {
        return paramName;
    }

    @Override
    public String getOriginalValue() {
        return originalValue;
    }

    @Override
    public org.zaproxy.zap.model.TechSet getTechSet() {
        return super.getTechSet();
    }

    /**
     * Returns true if the tech is a child of Tech.Db.
     *
     * @param tech the tech to check
     * @return true if the tech is a child of Tech.Db
     */
    private static boolean isDb(Tech tech) {
        Tech parent = tech.getParent();
        if (parent == null) {
            return false;
        }
        if (Tech.Db.equals(parent)) {
            return true;
        }
        return isDb(parent);
    }

    /**
     * Returns true if the tech is an SQL related tech. Explicitly excludes known no-sql techs,
     * mirroring baseline rule 40018's targeting.
     *
     * @param tech the tech to check
     * @return true if the supplied tech is SQL related
     */
    private static boolean isSqlDb(Tech tech) {
        if (Tech.MongoDB.equals(tech) || Tech.CouchDB.equals(tech)) {
            return false;
        }
        return isDb(tech);
    }

    @Override
    public boolean targets(TechSet technologies) {
        if (technologies.includes(Tech.Db)) {
            return true;
        }

        for (Tech tech : technologies.getIncludeTech()) {
            if (isSqlDb(tech)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int getRemainingBudget() {
        if (techniqueBudgets != null && techniqueBudgets.containsKey(currentTechnique)) {
            return techniqueBudgets.get(currentTechnique);
        }
        return 0;
    }

    @Override
    public ParameterContext getParameterContext() {
        return parameterContext;
    }

    @Override
    public HttpMessage getCachedBaseline() {
        return cachedBaseline;
    }

    @Override
    public HttpMessage getCachedControl() {
        return cachedControl;
    }

    @Override
    public HttpMessage getRepeatedBaseline() throws IOException {
        if (cachedRepeat == null) {
            cachedRepeat = getNewMsg();
            setParameter(cachedRepeat, paramName, originalValue);
            // Through the overridden sendAndReceive, so the replay is charged to the technique
            // that asked for it rather than sitting outside every budget like the baseline and
            // control do.
            sendAndReceive(cachedRepeat);
        }
        return cachedRepeat;
    }

    @Override
    public void recordBaselineMatch() {
        baselineMatches++;
    }

    @Override
    public void recordSuppressedDifferential() {
        suppressedDifferentials++;
    }

    /**
     * How many probes matched the baseline on the request scanned last — the gate every
     * differential technique passes before it can alert, summed over every parameter of the
     * request. A non-injectable row with a non-zero count is a near miss: the differential got its
     * first half and the alert was stopped only by the second.
     *
     * @return the number of baseline matches recorded
     */
    public int getBaselineMatchCount() {
        return baselineMatches;
    }

    /**
     * How many would-have-alerted differentials the error-status guard suppressed on the request
     * scanned last (rate limited, WAF, timed out), summed over every parameter of the request.
     *
     * @return the number of suppressed differentials recorded
     */
    public int getSuppressedDifferentialCount() {
        return suppressedDifferentials;
    }
}
