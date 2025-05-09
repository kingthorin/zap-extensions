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
package org.zaproxy.zap.extension.pscanrules;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.io.IOUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * A port from a Watcher passive scan rule (http://websecuritytool.codeplex.com/) rule
 * <tt>CasabaSecurity.Web.Watcher.Checks.CheckPasvJavaServerFacesViewState</tt>
 *
 * <p>All the
 *
 * <p>
 *
 * <pre>
 * Look for insecure ViewState used by Sun Java Mojarra (http://java.sun.com/javaee/javaserverfaces/) and
 * Apache MyFaces (http://myfaces.apache.org/).  Both are implementations of the JavaServer Faces standard
 * and both handle and reference ViewState the same way.
 * By default the ViewState data they pass between client and server is insecure and subject to tampering
 * and XSS attacks - see the advisory https://www.trustwave.com/spiderlabs/advisories/TWSL2010-001.txt.
 * </pre>
 *
 * <p>
 *
 * <pre>
 * David Byrne described it as this:
 * Regarding detection on JSF (Apache MyFaces & Sun Mojarra), they are Java object streams, so the format
 * is fairly predictable. The simplest way is probably to just check the value for plain text strings.
 * If it's unencrypted, there should be some Java class names, etc. in there. There are a few different
 * encodings that can be used though. All of the JSF view state's I've seen are base64 encoded,
 * although I don't think they have to be. After decoding the base64, some may be compressed
 * with the gzip algorithm (which is the default).
 * </pre>
 */
public class InsecureJsfViewStatePassiveScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    private static final String MESSAGE_PREFIX = "pscanrules.insecurejsfviewstate.";

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
                                CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG));
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    @Override
    public int getPluginId() {
        return 90001; // This is be changed if included in the ZAP code base
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (msg.getResponseBody().length() > 0 && msg.getResponseHeader().isText()) {
            List<Element> sourceElements = source.getAllElements(HTMLElementName.INPUT);
            if (sourceElements != null) {
                for (Element sourceElement : sourceElements) {

                    // Find ones where id="javax.faces.ViewState"
                    //
                    // TODO: Other possible field names include:
                    // jsf_state_64
                    // jsf_sequence
                    // jsf_tree
                    // jsf_tree_64
                    // jsf_viewid
                    // jsf_state
                    String src = sourceElement.getAttributeValue("id");
                    if (src != null && src.toLowerCase().contains("javax.faces.viewstate")) {
                        // Get the ViewState value
                        String val = sourceElement.getAttributeValue("value");
                        // Server-side ViewState usually comes down as an ID
                        // value like
                        // _id16683
                        // Ignoring these for now. Underscore is not a valid
                        // Base64 character
                        // so it's safe to ignore this.
                        if (val != null && val.startsWith("_")) {
                            return;
                        }

                        if (isViewStateStoredOnServer(val)) {
                            return;
                        }

                        // If the ViewState is not secured cryptographic
                        // protections then raise an alert.
                        if (!isViewStateSecure(val, msg.getRequestBody().getCharset())) {
                            createAlert(src).setMessage(msg).raise();
                        }
                    }
                }
            }
        }
    }

    /**
     * Checks whether the specified viewState is secure or possibly not
     *
     * @param viewState view state string
     * @param charset viewState string encoding
     * @return {@code true} if {@code viewState} is cryptographically secure, and {@code false}
     *     otherwise (there might be false positives and false negatives)
     */
    private static boolean isViewStateSecure(String viewState, String charset) {
        if (viewState == null || viewState.equals("")) {
            return true;
        }

        // /////////////////////////////
        // Base64 decode the ViewState and decompress ViewState from gzip format (the default),
        // or handle it as uncompressed (which is possible).
        //
        // There's two possibilities at this point, either the decoded ViewState
        // is uncompressed or it's compressed.
        // If it's uncompressed then we can treat it as a string right away.
        ///
        // TODO: Some ViewState can use other encoding forms, research and add
        // support for these.
        //
        // TODO: Could other compression forms be used?

        byte[] viewStateDecodeBytes;
        try {
            viewStateDecodeBytes = decompress(Base64.getDecoder().decode(viewState));
        } catch (IOException | IllegalArgumentException e) {
            // ViewState might be unencoded which is theoretically possible.
            return isRawViewStateSecure(viewState);
        }

        String viewStateDecoded = new String(viewStateDecodeBytes);

        // First attempt to treat the decoded ViewState as an uncompressed
        // string.
        if (!isRawViewStateSecure(viewStateDecoded)) {
            // ViewState is insecure
            return false;
        }

        return true;
    }

    private static byte[] decompress(byte[] value) throws IOException {
        if (value.length < 4) {
            return value;
        }
        int head = (value[0] & 0xff) | ((value[1] << 8) & 0xff00);
        if (GZIPInputStream.GZIP_MAGIC != head) {
            return value;
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (GZIPInputStream input = new GZIPInputStream(new ByteArrayInputStream(value))) {
            IOUtils.copy(input, output, 2048);
        }
        return output.toByteArray();
    }

    private static boolean isRawViewStateSecure(String viewState) {
        if (viewState == null || viewState.equals("")) {
            return true;
        }

        // Look for string values like 'java' to determine that it's insecure.
        // TODO: Improve this to look for more than just 'java'. It's possible
        // we could even have a false positive here.
        // Usually there will be Java class names in there as well as other
        // stuff.
        if (viewState.contains("java")) {
            return false;
        }

        return true;
    }

    private AlertBuilder createAlert(String viewState) {
        return newAlert()
                .setRisk(getRisk())
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setDescription(getDescription())
                .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "extrainfo", viewState))
                .setSolution(getSolution())
                .setReference(getReference())
                .setCweId(getCweId())
                .setWascId(getWascId());
    }

    // jsf server side implementation in com.sun.faces.renderkit.ServerSideStateHelper
    // two id's separated by :
    private static boolean isViewStateStoredOnServer(String val) {
        return val != null && val.contains(":");
    }

    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    public int getCweId() {
        return 642; // CWE-642: External Control of Critical State Data
    }

    public int getWascId() {
        return 14; // WASC Id - Server Misconfiguration
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                createAlert("<input type=\"hidden\" id=\"javax.faces.viewstate\" value=\"1231\"")
                        .build());
    }
}
