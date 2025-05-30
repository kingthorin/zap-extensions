/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;

/**
 * A class to actively check if the web server is configured to allow Cross Domain access, from a
 * malicious third party service, for instance. Currently checks for wildcards in Adobe's
 * crossdomain.xml, and in SilverLight's clientaccesspolicy.xml
 *
 * @author 70pointer@gmail.com
 */
public class CrossDomainScanRule extends AbstractHostPlugin implements CommonActiveScanRuleInfo {

    /** the logger object */
    private static final Logger LOGGER = LogManager.getLogger(CrossDomainScanRule.class);

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanbeta.crossdomain.";

    private static final String MESSAGE_PREFIX_ADOBE = "ascanbeta.crossdomain.adobe.";
    private static final String MESSAGE_PREFIX_ADOBE_READ = "ascanbeta.crossdomain.adobe.read.";
    private static final String MESSAGE_PREFIX_ADOBE_SEND = "ascanbeta.crossdomain.adobe.send.";
    private static final String MESSAGE_PREFIX_SILVERLIGHT = "ascanbeta.crossdomain.silverlight.";

    /** Adobe's cross domain policy file name */
    static final String ADOBE_CROSS_DOMAIN_POLICY_FILE = "crossdomain.xml";

    /** Silverlight's cross domain policy file name */
    static final String SILVERLIGHT_CROSS_DOMAIN_POLICY_FILE = "clientaccesspolicy.xml";

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                                CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                                CommonAlertTag.WSTG_V42_CONF_08_RIA_CROSS_DOMAIN));
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private DocumentBuilder docBuilder;
    private XPath xpath;

    @Override
    public int getId() {
        return 20016;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return "";
    }

    @Override
    public int getCategory() {
        return Category.SERVER;
    }

    @Override
    public String getSolution() {
        return "";
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public void init() {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        try {
            docBuilderFactory.setFeature(
                    "http://xml.org/sax/features/external-general-entities", false);
            docBuilderFactory.setFeature(
                    "http://xml.org/sax/features/external-parameter-entities", false);
            docBuilderFactory.setFeature(
                    "http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            docBuilderFactory.setExpandEntityReferences(false);
            docBuilder = docBuilderFactory.newDocumentBuilder();
            xpath = XPathFactory.newInstance().newXPath();
        } catch (ParserConfigurationException e) {
            LOGGER.error("Failed to create document builder:", e);
        }
    }

    /** scans the node for cross-domain mis-configurations */
    @Override
    public void scan() {
        if (docBuilder == null) {
            return;
        }

        try {
            // get the network details for the attack
            URI originalURI = this.getBaseMsg().getRequestHeader().getURI();

            scanAdobeCrossdomainPolicyFile(originalURI);

            scanSilverlightCrossdomainPolicyFile(originalURI);

        } catch (Exception e) {
            // needed to catch exceptions from the "finally" statement
            LOGGER.error(
                    "Error scanning a node for Cross Domain misconfigurations: {}",
                    e.getMessage(),
                    e);
        }
    }

    private void scanAdobeCrossdomainPolicyFile(URI originalURI)
            throws IOException, XPathExpressionException {
        // retrieve the Adobe cross domain policy file, and assess it
        HttpMessage crossdomainmessage =
                new HttpMessage(
                        new URI(
                                originalURI.getScheme(),
                                originalURI.getAuthority(),
                                "/" + ADOBE_CROSS_DOMAIN_POLICY_FILE,
                                null,
                                null));
        crossdomainmessage
                .getRequestHeader()
                .setVersion(getBaseMsg().getRequestHeader().getVersion());
        sendAndReceive(crossdomainmessage, false);

        if (crossdomainmessage.getResponseBody().length() == 0) {
            return;
        }

        byte[] crossdomainmessagebytes = crossdomainmessage.getResponseBody().getBytes();

        // parse the file. If it's not parseable, it might have been because of a 404
        try {
            // work around the "no protocol" issue by wrapping the content in a ByteArrayInputStream
            Document adobeXmldoc =
                    docBuilder.parse(
                            new InputSource(new ByteArrayInputStream(crossdomainmessagebytes)));

            // check for cross domain read (data load) access
            XPathExpression exprAllowAccessFromDomain =
                    xpath.compile(
                            "/cross-domain-policy/allow-access-from/@domain"); // gets the domain
            // attributes
            NodeList exprAllowAccessFromDomainNodes =
                    (NodeList)
                            exprAllowAccessFromDomain.evaluate(adobeXmldoc, XPathConstants.NODESET);
            for (int i = 0; i < exprAllowAccessFromDomainNodes.getLength(); i++) {
                String domain = exprAllowAccessFromDomainNodes.item(i).getNodeValue();
                if (domain.equals("*")) {
                    // oh dear me.
                    buildAdobeReadAlert().setMessage(crossdomainmessage).raise();
                }
            }
            // check for cross domain send (upload) access
            XPathExpression exprRequestHeadersFromDomain =
                    xpath.compile(
                            "/cross-domain-policy/allow-http-request-headers-from/@domain"); // gets
            // the
            // domain attributes
            NodeList exprRequestHeadersFromDomainNodes =
                    (NodeList)
                            exprRequestHeadersFromDomain.evaluate(
                                    adobeXmldoc, XPathConstants.NODESET);
            for (int i = 0; i < exprRequestHeadersFromDomainNodes.getLength(); i++) {
                String domain = exprRequestHeadersFromDomainNodes.item(i).getNodeValue();
                if (domain.equals("*")) {
                    // oh dear, dear me.
                    buildAdobeSendAlert().setMessage(crossdomainmessage).raise();
                }
            }
        } catch (SAXException | IOException e) {
            // Could well be a 404 or equivalent
            LOGGER.debug(
                    "An error occurred trying to parse {} as XML {}",
                    ADOBE_CROSS_DOMAIN_POLICY_FILE,
                    e);
        }
    }

    private AlertBuilder buildAdobeAlert(String ref) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX_ADOBE + "desc"))
                .setAlertRef(getId() + ref);
    }

    private AlertBuilder buildAdobeReadAlert() {
        return buildAdobeAlert("-1")
                .setName(Constant.messages.getString(MESSAGE_PREFIX_ADOBE_READ + "name"))
                .setOtherInfo(
                        Constant.messages.getString(
                                MESSAGE_PREFIX_ADOBE_READ + "extrainfo",
                                "/" + ADOBE_CROSS_DOMAIN_POLICY_FILE))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX_ADOBE_READ + "soln"))
                .setEvidence("<allow-access-from domain=\"*\"");
    }

    private AlertBuilder buildAdobeSendAlert() {
        return buildAdobeAlert("-2")
                .setName(Constant.messages.getString(MESSAGE_PREFIX_ADOBE_SEND + "name"))
                .setOtherInfo(
                        Constant.messages.getString(
                                MESSAGE_PREFIX_ADOBE_SEND + "extrainfo",
                                "/" + ADOBE_CROSS_DOMAIN_POLICY_FILE))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX_ADOBE_SEND + "soln"))
                .setEvidence("<allow-http-request-headers-from domain=\"*\"");
    }

    private void scanSilverlightCrossdomainPolicyFile(URI originalURI)
            throws IOException, XPathExpressionException {
        // retrieve the Silverlight client access policy file, and assess it.
        HttpMessage clientaccesspolicymessage =
                new HttpMessage(
                        new URI(
                                originalURI.getScheme(),
                                originalURI.getAuthority(),
                                "/" + SILVERLIGHT_CROSS_DOMAIN_POLICY_FILE,
                                null,
                                null));
        clientaccesspolicymessage
                .getRequestHeader()
                .setVersion(getBaseMsg().getRequestHeader().getVersion());
        sendAndReceive(clientaccesspolicymessage, false);

        if (clientaccesspolicymessage.getResponseBody().length() == 0) {
            return;
        }

        byte[] clientaccesspolicymessagebytes =
                clientaccesspolicymessage.getResponseBody().getBytes();

        // parse the file. If it's not parseable, it might have been because of a 404
        try {
            // work around the "no protocol" issue by wrapping the content in a ByteArrayInputStream
            Document silverlightXmldoc =
                    docBuilder.parse(
                            new InputSource(
                                    new ByteArrayInputStream(clientaccesspolicymessagebytes)));
            XPathExpression exprAllowFromUri =
                    xpath.compile(
                            "/access-policy/cross-domain-access/policy/allow-from/domain/@uri"); // gets the uri attributes
            // check the "allow-from" policies
            NodeList exprAllowFromUriNodes =
                    (NodeList) exprAllowFromUri.evaluate(silverlightXmldoc, XPathConstants.NODESET);
            for (int i = 0; i < exprAllowFromUriNodes.getLength(); i++) {
                String uri = exprAllowFromUriNodes.item(i).getNodeValue();
                if (uri.equals("*")) {
                    // tut, tut, tut.
                    LOGGER.debug(
                            "Bingo! {}, at /access-policy/cross-domain-access/policy/allow-from/domain/@uri",
                            SILVERLIGHT_CROSS_DOMAIN_POLICY_FILE);
                    buildSilverlightAlert().setMessage(clientaccesspolicymessage).raise();
                }
            }

        } catch (SAXException | IOException e) {
            // Could well be a 404 or equivalent
            LOGGER.debug(
                    "An error occurred trying to parse {} as XML {}",
                    SILVERLIGHT_CROSS_DOMAIN_POLICY_FILE,
                    e);
        }
    }

    private AlertBuilder buildSilverlightAlert() {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setName(Constant.messages.getString(MESSAGE_PREFIX_SILVERLIGHT + "name"))
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX_SILVERLIGHT + "desc"))
                .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX_SILVERLIGHT + "extrainfo"))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX_SILVERLIGHT + "soln"))
                .setEvidence("<domain uri=\"*\"")
                .setAlertRef(getId() + "-3");
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 264; // CWE 264: Permissions, Privileges, and Access Controls
        // the more specific CWE's under this one are not rally relevant
    }

    @Override
    public int getWascId() {
        return 14; // WASC-14: Server Misconfiguration
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                buildAdobeReadAlert().build(),
                buildAdobeSendAlert().build(),
                buildSilverlightAlert().build());
    }
}
