/*
 *
 * Paros and its related class files.
 *
 * Paros is an HTTP/HTTPS proxy for assessing web application security.
 * Copyright (C) 2003-2004 Chinotec Technologies Company
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the Clarified Artistic License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Clarified Artistic License for more details.
 *
 * You should have received a copy of the Clarified Artistic License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
// ZAP: 2012/01/02 Separate param and attack
// ZAP: 2012/04/25 Added @Override annotation to all appropriate methods.
// ZAP: 2012/12/28 Issue 447: Include the evidence in the attack field
// ZAP: 2013/01/25 Removed the "(non-Javadoc)" comments.
// ZAP: 2013/03/03 Issue 546: Remove all template Javadoc comments
// ZAP: 2013/07/19 Issue 366: "Other Info" for "Session ID in URL rewrite" not always correct
// ZAP: 2013/10/12 Issue 809: Converted to a passive scan rule and added some new features
// ZAP: 2014/11/09 Issue 1396: Add min length check to reduce false positives
// ZAP: 2015/09/23 Issue 1594: Change matching mechanism
// ZAP: 2017/11/10 Remove N/A from alert parameter.
// ZAP: 2019/05/08 Normalise format/indentation.
// ZAP: 2019/07/11 Change URL regex to find unquoted URLs in HREFs/SRC tags.
// ZAP: 2020/06/22 Normalise scan rule class naming and i18n keys.
package org.zaproxy.zap.extension.pscanrules;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.httpsessions.HttpSessionsParam;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Plugin refactored for URL ID session disclosure starting from the previous Active plugin
 * developed by Paros team
 *
 * @author yhawke
 * @author kingthorin+owaspzap
 */
public class InfoSessionIdUrlScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.infosessionidurl.";

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
                                CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED,
                                CommonAlertTag.WSTG_V42_SESS_04_SESS_EXPOSED));
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        alertTags.put(PolicyTag.DEV_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private static final int SESSION_TOKEN_MIN_LENGTH = 8;

    /*
     * This scan rule looks for session ID tokens as defined in
     * HttpSessionsParam.DEFAULT_TOKENS. They generally look like these: ASP =
     * ASPSESSIONIDxxxxx=xxxxxx PHP = PHPSESSID Cold fusion = CFID, CFTOKEN
     * (confirmed, checked with Macromedia) Java (tomcat, jrun, websphere, sunone,
     * weblogic )= JSESSIONID=xxxxx
     *
     * List of session id available also on this site:
     * http://www.portent.com/blog/random/session-id-parameters-list.htm
     */

    /**
     * Get this plugin id
     *
     * @return the ZAP id
     */
    @Override
    public int getPluginId() {
        return 00003;
    }

    /**
     * Get the plugin name
     *
     * @return the plugin name
     */
    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private static String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private static String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    private static final Pattern PATHSESSIONIDPATTERN =
            Pattern.compile(
                    "jsessionid=[\\dA-Z]{" + SESSION_TOKEN_MIN_LENGTH + ",}",
                    Pattern.CASE_INSENSITIVE);

    /**
     * Perform passive scanning for URL based session IDs in the HTTP request. TODO: This method
     * should really scan the contents of the response to see if it is HTML, and if so, look for
     * HREFs and SRC tags and check if the URLs in them contain session IDs. This would enable ZAP
     * to detect Session IDs in URLs exactly where they are occurring, rather than simply detecting
     * the symptom of the problem in URLs of requests.
     *
     * @param msg the message that needs to be checked
     * @param id the id of the session
     * @param source the source code of the response
     */
    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        TreeSet<HtmlParameter> urlParams = msg.getUrlParams();

        boolean found = false;

        // The Session ID list from option param (panel)
        OptionsParam options = Model.getSingleton().getOptionsParam();
        HttpSessionsParam sessionOptions = options.getParamSet(HttpSessionsParam.class);
        List<String> sessionIds = Collections.emptyList();
        if (sessionOptions != null) {
            sessionIds = sessionOptions.getDefaultTokensEnabled();
        }

        if (!urlParams.isEmpty()) {
            for (HtmlParameter param : urlParams) { // Iterate through the parameters
                // If the parameter name is one of those on the Session Token list from the options
                // panel
                if (sessionIds.contains(param.getName().toLowerCase(Locale.ROOT))) {
                    // If the param value length is greater than MIN_LENGTH (therefore there is a
                    // value)
                    if (param.getValue().length() > SESSION_TOKEN_MIN_LENGTH) {
                        createAlert(
                                        getName(),
                                        getDescription(),
                                        getSolution(),
                                        Alert.CONFIDENCE_HIGH,
                                        param.getValue(),
                                        param.getName(),
                                        "-1")
                                .raise();
                        // We don't break on this one.
                        // There shouldn't be more than one per URL but bizarre things do happen.
                        // Improbable doesn't mean impossible.
                        found = true;
                    }
                }
            }
        }

        if (!found && msg.getRequestHeader().getURI().getEscapedPath() != null) {
            // Handle jsessionid like:
            // http://tld.gtld/fred;jsessionid=1A530637289A03B07199A44E8D531427?foo=bar
            Matcher jsessMatcher = null;
            try {
                jsessMatcher =
                        PATHSESSIONIDPATTERN.matcher(msg.getRequestHeader().getURI().getPath());
            } catch (URIException e) {
            }
            if (jsessMatcher != null && jsessMatcher.find()) {
                createAlert(
                                getName(),
                                getDescription(),
                                getSolution(),
                                Alert.CONFIDENCE_HIGH,
                                jsessMatcher.group(),
                                "",
                                "-2")
                        .raise();
                found = true;
            }
        }
        if (found) {
            // Now try to check if there exists a referer inside the content
            // i.e.: There is an external link for which
            // a referer header would be passed including this session token
            try {
                checkSessionIDExposureTo3rdParty(msg, id);
            } catch (URIException e) {
            }
        }
    }

    // External link Response finder regex
    // HTML is very simple because only src/href exists
    // DOM based is very complex because you can have all these possibilities:
    // window.open('url
    // window.location='url
    // location.href='url
    // document.location='url
    // and also internal variables containing URLs that can be
    // also dynamically composed along page execution
    // so we search only for pattern like these:
    // ='url or ('url because it's suitable to all the previous possibilities
    // and we check for unquoted URLs only if href or src
    // ---------------------------------
    private static final String EXT_LINK = "https?://([\\w\\.\\-_]+)";
    private static final Pattern[] EXT_LINK_PATTERNS = {
        Pattern.compile("src\\s*=\\s*[\"']?" + EXT_LINK, Pattern.CASE_INSENSITIVE),
        Pattern.compile("href\\s*=\\s*[\"']?" + EXT_LINK, Pattern.CASE_INSENSITIVE),
        // This regex looks for DOM URLs (per above)
        Pattern.compile("[=\\(]\\s*[\"']" + EXT_LINK, Pattern.CASE_INSENSITIVE)
    };

    // The name of this sub-alert
    private static String getRefererAlert() {
        return Constant.messages.getString(MESSAGE_PREFIX + "referrer.alert");
    }

    // The description of this sub-alert
    private static String getRefererDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "referrer.desc");
    }

    // The solution of this sub-alert
    private static String getRefererSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "referrer.soln");
    }

    /**
     * Checks if the session ID in the URL might be exposed to 3rd-parties via a link to that 3rd
     * party in the response body. For example: <a href="http://other.domain.tld/">link</a>. The
     * referer header value sent to the 3rd party will include the URL with the included session ID.
     * This method should only be invoked if the requesting URL includes a session ID.
     *
     * @param msg the message that needs to be checked
     * @param id the id of the session
     * @throws URIException if there's some trouble with the Request
     */
    private void checkSessionIDExposureTo3rdParty(HttpMessage msg, int id) throws URIException {

        String body = msg.getResponseBody().toString();
        String host = msg.getRequestHeader().getURI().getHost();
        String linkHostName;
        Matcher matcher;

        for (Pattern pattern : EXT_LINK_PATTERNS) {
            matcher = pattern.matcher(body);

            if (matcher.find()) {
                linkHostName = matcher.group(1);
                if (host.compareToIgnoreCase(linkHostName) != 0) {
                    createAlert(
                                    getRefererAlert(),
                                    getRefererDescription(),
                                    getRefererSolution(),
                                    Alert.CONFIDENCE_MEDIUM,
                                    linkHostName,
                                    "",
                                    "-3")
                            .setRisk(
                                    msg.getRequestHeader().isSecure()
                                            ? Alert.RISK_MEDIUM
                                            : Alert.RISK_LOW)
                            .raise();

                    break; // Only need one
                }
            }
        }
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        alerts.add(
                createAlert(
                                getName(),
                                getDescription(),
                                getSolution(),
                                Alert.CONFIDENCE_HIGH,
                                "1A530637289A03B07199A44E8D531427",
                                "jsessionid",
                                "-1")
                        .build());
        alerts.add(
                createAlert(
                                getName(),
                                getDescription(),
                                getSolution(),
                                Alert.CONFIDENCE_HIGH,
                                "jsessionid=1A530637289A03B07199A44E8D531427",
                                "",
                                "-2")
                        .build());
        alerts.add(
                createAlert(
                                getRefererAlert(),
                                getRefererDescription(),
                                getRefererSolution(),
                                Alert.CONFIDENCE_MEDIUM,
                                "www.example.org",
                                "",
                                "-3")
                        .build());
        return alerts;
    }

    private AlertBuilder createAlert(
            String name,
            String desc,
            String soln,
            int confidence,
            String evidence,
            String param,
            String alertRef) {
        return newAlert()
                .setName(name)
                .setRisk(Alert.RISK_MEDIUM)
                .setConfidence(confidence)
                .setDescription(desc)
                .setSolution(soln)
                .setReference(Constant.messages.getString(MESSAGE_PREFIX + "refs"))
                .setParam(param)
                .setEvidence(evidence)
                .setCweId(598) // CWE-598: Use of GET Request Method With Sensitive Query Strings
                .setWascId(13) // WASC Id - Info leakage
                .setAlertRef(getPluginId() + alertRef);
    }
}
