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
package org.zaproxy.zap.extension.soap;

import jakarta.xml.soap.SOAPException;
import jakarta.xml.soap.SOAPMessage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpMessage;
import org.w3c.dom.NodeList;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;

/**
 * SOAP XML Injection Active scan rule
 *
 * @author Albertov91
 */
public class SOAPXMLInjectionActiveScanRule extends AbstractAppParamPlugin
        implements CommonScanRuleInfo {

    private static final String MESSAGE_PREFIX = "soap.soapxmlinjection.";
    private static final Logger LOGGER = LogManager.getLogger(SOAPXMLInjectionActiveScanRule.class);
    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A01_INJECTION));
        alertTags.put(PolicyTag.API.getTag(), "");
        alertTags.put(PolicyTag.DEV_CICD.getTag(), "");
        alertTags.put(PolicyTag.DEV_STD.getTag(), "");
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    @Override
    public int getId() {
        return 90029;
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
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public void scan(HttpMessage msg, String paramName, String paramValue) {
        try {
            /* This scan is only applied to SOAP messages. */
            if (this.isStop()) return;
            if (isSoapMessage(msg.getRequestBody())) {
                String paramValue2 = paramValue + "_modified";
                String finalValue =
                        paramValue + "</" + paramName + "><" + paramName + ">" + paramValue2;
                /* Request message that contains the modified value. */
                HttpMessage modifiedMsg = craftAttackMessage(msg, paramName, paramValue2);
                if (modifiedMsg == null) return;
                /* Request message that contains the XML code to be injected. */
                HttpMessage attackMsg = craftAttackMessage(msg, paramName, finalValue);
                /* Sends the modified request. */
                if (this.isStop()) return;
                sendAndReceive(modifiedMsg);
                if (this.isStop()) return;
                sendAndReceive(attackMsg);
                if (this.isStop()) return;
                /* Analyzes the response. */
                final HttpMessage originalMsg = getBaseMsg();
                if (this.isStop()) return;
                String soapVersionInfo =
                        originalMsg.getRequestHeader().getHeader("SOAPAction") != null
                                ? " SOAP version 1.1."
                                : " SOAP version 1.2.";
                if (!isSoapMessage(attackMsg.getResponseBody())) {
                    /*
                     * Response has no SOAP format. It is still notified since it is an unexpected
                     * result.
                     */
                    newAlert()
                            .setRisk(Alert.RISK_LOW)
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setAttack(finalValue)
                            .setOtherInfo(
                                    Constant.messages.getString(MESSAGE_PREFIX + "warn1")
                                            + soapVersionInfo)
                            .setMessage(attackMsg)
                            .raise();
                } else if (responsesAreEqual(modifiedMsg, attackMsg)
                        && !(responsesAreEqual(originalMsg, modifiedMsg))) {
                    /*
                     * The attack message has achieved the same result as the modified message, so
                     * XML injection attack worked.
                     */
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setAttack(finalValue)
                            .setOtherInfo(
                                    Constant.messages.getString(MESSAGE_PREFIX + "warn2")
                                            + soapVersionInfo)
                            .setMessage(attackMsg)
                            .raise();
                }
            }
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    /* Checks whether server response follows a SOAP message format. */
    private boolean isSoapMessage(HttpBody msgBody) {
        if (msgBody.length() <= 0) return false;
        try {
            SOAPMessage soapMsg = SoapMessageFactory.createMessage(msgBody);
            /* Content has been parsed correctly as SOAP content. */
            return soapMsg != null;
        } catch (Exception e) {
            /*
             * Error when trying to parse as SOAP content. It is considered as a non-SOAP
             * message.
             */
            return false;
        }
    }

    protected HttpMessage craftAttackMessage(HttpMessage msg, String paramName, String finalValue) {
        try {
            SOAPMessage soapMsg = SoapMessageFactory.createMessage(msg.getRequestBody());
            if (soapMsg == null) {
                LOGGER.debug("Not a SOAP message.");
                return null;
            }
            NodeList nodeList = soapMsg.getSOAPBody().getElementsByTagName(paramName);
            if (nodeList.getLength() == 0) {
                LOGGER.debug("Not a SOAP element: {}", paramName);
                return null;
            }
            nodeList.item(0).setTextContent(finalValue);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            soapMsg.writeTo(outputStream);
            HttpMessage attackMsg = new HttpMessage(msg);
            attackMsg.setRequestBody(StringEscapeUtils.unescapeXml(outputStream.toString()));
            return attackMsg;
        } catch (SOAPException | IOException e) {
            LOGGER.warn("Malformed SOAP Message.");
            return null;
        }
    }

    private boolean responsesAreEqual(HttpMessage original, HttpMessage crafted) {
        return original.getResponseBody().toString().equals(crafted.getResponseBody().toString());
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 91; // CWE-91: XML Injection
    }

    @Override
    public int getWascId() {
        // The WASC ID
        return 0;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
