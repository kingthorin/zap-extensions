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

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.DiceMatcher;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.zap.model.Tech;

/**
 * a scan rule that looks for application source code disclosure using path traversal techniques
 *
 * @author 70pointer
 */
public class SourceCodeDisclosureFileInclusionScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    // use a random file name which is very unlikely to exist
    private static final String NON_EXISTANT_FILENAME =
            RandomStringUtils.secure().next(38, "abcdefghijklmnopqrstuvwxyz");

    // the prefixes to try for source file inclusion
    private String[] LOCAL_SOURCE_FILE_TARGET_PREFIXES = {
        "",
        "/",
        "../",
        "webapps/" // in the case of servlet containers like Tomcat, JBoss (etc.), sometimes the
        // working directory is the application server folder
    };

    // the prefixes to try for WAR/EAR file inclusion
    private String[] LOCAL_WAR_EAR_FILE_TARGET_PREFIXES = {
        "/../" // for Tomcat, if the current directory is the tomcat/webapps/appname folder, when
        // slashes ARE NOT added by the code (far less common in practice than I would have
        // thought, given some real world vulnerable apps.)
        ,
        "../" // for Tomcat, if the current directory is the tomcat/webapps/appname folder, when
        // slashes ARE added by the code (far less common in practice than I would have
        // thought, given some real world vulnerable apps.)
        ,
        "/../../" // for Tomcat, if the current directory is the tomcat/webapps/appname/a/ folder,
        // when slashes ARE NOT added by the code
        ,
        "../../" // for Tomcat, if the current directory is the tomcat/webapps/appname/a/ folder,
        // when slashes ARE added by the code
        ,
        "/../../../" // for Tomcat, if the current directory is the tomcat/webapps/appname/a/b/
        // folder, when slashes ARE NOT added by the code
        ,
        "../../../" // for Tomcat, if the current directory is the tomcat/webapps/appname/a/b/
        // folder, when slashes ARE added by the code
        ,
        "/../../../../" // for Tomcat, if the current directory is the tomcat/webapps/appname/a/b/c/
        // folder, when slashes ARE NOT added by the code
        ,
        "../../../../" // for Tomcat, if the current directory is the tomcat/webapps/appname/a/b/c/
        // folder, when slashes ARE added by the code
        ,
        "/webapps/" // for Tomcat, if the current directory is the tomcat folder, when slashes ARE
        // NOT added by the code
        ,
        "webapps/" // for Tomcat, if the current directory is the tomcat folder, when slashes ARE
        // added by the code
        ,
        "/" // for Tomcat, if the current directory is the tomcat/webapps folder, when slashes ARE
        // NOT added by the code
        ,
        "" // for Tomcat, if the current directory is the tomcat/webapps folder, when slashes ARE
        // added by the code
        ,
        "/../webapps/" // for Tomcat, if the current directory is the tomcat/temp folder, when
        // slashes ARE NOT added by the code
        ,
        "../webapps/" // for Tomcat, if the current directory is the tomcat/temp folder, when
        // slashes ARE added by the code
    };

    /** details of the vulnerability which we are attempting to find 33 = "Path Traversal" */
    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("wasc_33");

    /** the logger object */
    private static final Logger LOGGER =
            LogManager.getLogger(SourceCodeDisclosureFileInclusionScanRule.class);

    /**
     * the threshold for whether 2 responses match. depends on the alert threshold set in the GUI.
     * not final or static.
     */
    int thresholdPercentage = 0;

    /**
     * patterns expected in the output for common server side file extensions TODO: add support for
     * verification of other file types, once I get some real world test cases.
     */
    private static final Pattern PATTERN_JSP = Pattern.compile("<%.*%>");

    private static final Pattern PATTERN_PHP = Pattern.compile("<?php");
    private static final Pattern PATTERN_JAVA =
            Pattern.compile(
                    "class"); // Java is compiled, not interpreted, but this helps with my test
    // cases.
    private static final Pattern PATTERN_HTML =
            Pattern.compile(
                    "<html"); // helps eliminate some common false positives in the case of 403s,
    // 302s, etc.

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                                CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG));
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    /** returns the plugin id */
    @Override
    public int getId() {
        return 43;
    }

    /** returns the name of the plugin */
    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.sourcecodedisclosure.lfibased.name");
    }

    @Override
    public String getDescription() {
        return VULN.getDescription();
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }

    @Override
    public String getSolution() {
        return VULN.getSolution();
    }

    @Override
    public String getReference() {
        return VULN.getReferencesAsString();
    }

    @Override
    public void init() {
        switch (this.getAlertThreshold()) {
            case HIGH:
                this.thresholdPercentage = 95;
                break;
            case MEDIUM:
                this.thresholdPercentage = 75;
                break;
            case LOW:
                this.thresholdPercentage = 50;
                break;
            default:
        }
    }

    /** scan everything except URL path parameters, if these were enabled */
    @Override
    public void scan(HttpMessage msg, NameValuePair originalParam) {
        /*
         * Scan everything _except_ URL path parameters, if these were enabled.
         * Changing the URL path parameter *typically* causes a completely different file to be loaded, which causes false positives for this rule.
         */
        if (originalParam.getType() != NameValuePair.TYPE_URL_PATH) {
            super.scan(msg, originalParam);
        }
    }

    /**
     * scans the given parameter for source code disclosure vulnerabilities, using path traversal
     * vulnerabilities
     */
    @Override
    public void scan(HttpMessage originalmsg, String paramname, String paramvalue) {
        if (isClientError(getBaseMsg()) || isServerError(getBaseMsg())) {
            return;
        }
        try {
            URI uri = originalmsg.getRequestHeader().getURI();
            String path = uri.getPath();
            if (path == null || "/".equals(path)) {
                // No path or empty path, no point continuing.
                return;
            }

            LOGGER.debug("Attacking at Attack Strength: {}", this.getAttackStrength());
            LOGGER.debug(
                    "Checking [{}] [{}], parameter [{}], with original value [{}] for Source Code Disclosure",
                    getBaseMsg().getRequestHeader().getMethod(),
                    getBaseMsg().getRequestHeader().getURI(),
                    paramname,
                    paramvalue);
            // the response of the original message is not populated! so populate it.
            sendAndReceive(originalmsg, false); // do not follow redirects

            // first send a query for a random parameter value
            // then try a query for the file paths and names that we are using to try to get out the
            // source code for the current URL
            HttpMessage randomfileattackmsg = getNewMsg();
            setParameter(randomfileattackmsg, paramname, NON_EXISTANT_FILENAME);
            sendAndReceive(randomfileattackmsg, false); // do not follow redirects

            int originalversusrandommatchpercentage =
                    DiceMatcher.getMatchPercentage(
                            originalmsg.getResponseBody().toString(),
                            randomfileattackmsg.getResponseBody().toString());
            if (isEmptyOrTooSimilar(randomfileattackmsg, originalversusrandommatchpercentage)) {
                LOGGER.debug(
                        "The output for a non-existent filename [{}] does not sufficiently differ from that of the original parameter [{}], "
                                + " (or the response was empty) at {}%, compared to a threshold of {}%",
                        NON_EXISTANT_FILENAME,
                        paramvalue,
                        originalversusrandommatchpercentage,
                        this.thresholdPercentage);
                return;
            }

            if (this.isStop()) {
                LOGGER.debug("Stopped, due to a user request");
                return;
            }

            // at this point, there was a sufficient difference between the random filename and the
            // original parameter
            // so lets try the various path names that might point at the source code for this URL
            String pathMinusLeadingSlash = uri.getPath().substring(1);
            String pathMinusApplicationContext =
                    uri.getPath().substring(uri.getPath().indexOf("/", 1) + 1);

            // in the case of wavsep, should give us "wavsep"
            // use this later to build up "wavsep.war", and "wavsep.ear", for instance :)
            String applicationContext = "";
            int slashIndex = uri.getPath().indexOf("/", 1);
            if (slashIndex > 1) {
                applicationContext = uri.getPath().substring(1, slashIndex);
            }

            // all of the sourceFileNames should *not* lead with a slash.
            String[] sourceFileNames = {
                uri.getName(), pathMinusLeadingSlash, pathMinusApplicationContext
            };

            // and get the file extension (in uppercase), so we can switch on it (if there was an
            // extension, that is)
            String fileExtension = null;
            if (uri.getName().contains(".")) {
                fileExtension = uri.getName().substring(uri.getName().lastIndexOf(".") + 1);
                fileExtension = fileExtension.toUpperCase();
            }

            // for each of the file names in turn, try it with each of the prefixes
            for (String sourcefilename : sourceFileNames) {
                LOGGER.debug("Source file is [{}]", sourcefilename);
                // for the url filename, try each of the prefixes in turn
                for (int h = 0; h < LOCAL_SOURCE_FILE_TARGET_PREFIXES.length; h++) {

                    String prefixedUrlfilename =
                            LOCAL_SOURCE_FILE_TARGET_PREFIXES[h] + sourcefilename;
                    LOGGER.debug("Trying file name [{}]", prefixedUrlfilename);

                    HttpMessage sourceattackmsg = getNewMsg();
                    setParameter(sourceattackmsg, paramname, prefixedUrlfilename);
                    // send the modified message (with the url filename), and see what we get back
                    sendAndReceive(sourceattackmsg, false); // do not follow redirects

                    int randomversussourcefilenamematchpercentage =
                            DiceMatcher.getMatchPercentage(
                                    randomfileattackmsg.getResponseBody().toString(),
                                    sourceattackmsg.getResponseBody().toString());
                    if (isEmptyOrTooSimilar(
                            sourceattackmsg, randomversussourcefilenamematchpercentage)) {
                        LOGGER.debug(
                                "The output for the source code filename [{}] does not sufficiently "
                                        + "differ from that of the random parameter (or was empty), at {}%, compared to a threshold of {}%",
                                prefixedUrlfilename,
                                randomversussourcefilenamematchpercentage,
                                this.thresholdPercentage);
                    } else {
                        // if we verified the response
                        if (dataMatchesExtension(
                                sourceattackmsg.getResponseBody().getBytes(), fileExtension)) {
                            LOGGER.debug(
                                    "Source code disclosure!  The output for the source code filename [{}] differs sufficiently from that of the random parameter, at {}%, compared to a threshold of {}%",
                                    prefixedUrlfilename,
                                    randomversussourcefilenamematchpercentage,
                                    this.thresholdPercentage);

                            // if we get to here, it is very likely that we have source file
                            // inclusion attack. alert it.
                            createAlert(
                                            paramname,
                                            prefixedUrlfilename,
                                            randomversussourcefilenamematchpercentage,
                                            sourceattackmsg,
                                            getBaseMsg().getRequestHeader().getURI().toString())
                                    .raise();
                            // All done on this parameter
                            return;
                        } else {
                            LOGGER.debug(
                                    "Could not verify that the HTML output is source code of type {}. Next!",
                                    fileExtension);
                        }
                    }
                    if (this.isStop()) {
                        LOGGER.debug("Stopped, due to a user request");
                        return;
                    }
                }
            }

            if (!inScope(Tech.Tomcat)) {
                return;
            }

            // if the above fails, get the entire WAR/EAR
            // but only if in HIGH or INSANE attack strength, since this generates more work and
            // slows Zap down badly if it actually
            // finds and returns the application WAR file!

            if (this.getAttackStrength() == AttackStrength.INSANE
                    || this.getAttackStrength() == AttackStrength.HIGH) {

                // all of the warearFileNames should *not* lead with a slash.
                // TODO: should we consider uppercase / lowercase on (real) OSs such as Linux that
                // support such a thing?
                // Note that each of these file types can contain the Java class files, which can be
                // disassembled into the Java source code.
                // this in fact is one of my favourite hacking techniques.
                String[] warearFileNames = {
                    applicationContext + ".war",
                    applicationContext + ".ear",
                    applicationContext + ".rar"
                };

                // for each of the EAR / file names in turn, try it with each of the prefixes
                for (String sourcefilename : warearFileNames) {
                    LOGGER.debug("WAR/EAR file is [{}]", sourcefilename);
                    // for the url filename, try each of the prefixes in turn
                    for (int h = 0; h < LOCAL_WAR_EAR_FILE_TARGET_PREFIXES.length; h++) {

                        String prefixedUrlfilename =
                                LOCAL_WAR_EAR_FILE_TARGET_PREFIXES[h] + sourcefilename;
                        LOGGER.debug("Trying WAR/EAR file name [{}]", prefixedUrlfilename);

                        HttpMessage sourceattackmsg = getNewMsg();
                        setParameter(sourceattackmsg, paramname, prefixedUrlfilename);
                        // send the modified message (with the url filename), and see what we get
                        // back
                        sendAndReceive(sourceattackmsg, false); // do not follow redirects
                        LOGGER.debug("Completed WAR/EAR file name [{}]", prefixedUrlfilename);

                        // since the WAR/EAR file may be large, and since the LCS does not work well
                        // with such large files, lets just look at the file size,
                        // compared to the original
                        int randomversussourcefilenamematchpercentage =
                                calcLengthMatchPercentage(
                                        sourceattackmsg.getResponseBody().length(),
                                        randomfileattackmsg.getResponseBody().length());
                        if (randomversussourcefilenamematchpercentage < this.thresholdPercentage) {
                            LOGGER.debug(
                                    "Source code disclosure!  The output for the WAR/EAR filename [{}] differs sufficiently (in length) from that of the random parameter, at {}%, compared to a threshold of {}%",
                                    prefixedUrlfilename,
                                    randomversussourcefilenamematchpercentage,
                                    this.thresholdPercentage);

                            // Note: no verification of the file contents in this case.

                            // if we get to here, it is very likely that we have source file
                            // inclusion attack. alert it.
                            createAlert(
                                            paramname,
                                            prefixedUrlfilename,
                                            randomversussourcefilenamematchpercentage,
                                            sourceattackmsg,
                                            getBaseMsg().getRequestHeader().getURI().toString())
                                    .raise();

                            // All done. No need to look for vulnerabilities on subsequent
                            // parameters on the same request (to reduce performance impact)
                            return;
                        } else {
                            LOGGER.debug(
                                    "The output for the WAR/EAR code filename [{}] does not sufficiently differ in length from that of the random parameter, at {}%, compared to a threshold of {}%",
                                    prefixedUrlfilename,
                                    randomversussourcefilenamematchpercentage,
                                    this.thresholdPercentage);
                        }
                        if (this.isStop()) {
                            LOGGER.debug("Stopped, due to a user request");
                            return;
                        }
                    }
                }
            } else {
                LOGGER.debug(
                        "Not checking for EAR/WAR files for this request, since the Attack Strength is not HIGH or INSANE");
            }

        } catch (Exception e) {
            LOGGER.error(
                    "Error scanning parameters for Source Code Disclosure: {}", e.getMessage(), e);
        }
    }

    private boolean isEmptyOrTooSimilar(HttpMessage msg, int matchPercentage) {
        return msg.getResponseBody().length() == 0 || matchPercentage > this.thresholdPercentage;
    }

    /**
     * returns whether the message response content matches the specified extension
     *
     * @param data
     * @param fileExtension
     * @return
     */
    private static boolean dataMatchesExtension(byte[] data, String fileExtension) {
        if (fileExtension != null) {
            if (fileExtension.equals("JSP")) {
                if (PATTERN_JSP.matcher(new String(data)).find()) return true;
            } else if (fileExtension.equals("PHP")) {
                if (PATTERN_PHP.matcher(new String(data)).find()) return true;
            } else if (fileExtension.equals("JAVA")) {
                if (PATTERN_JAVA.matcher(new String(data)).find()) return true;
            } else if (fileExtension.equals("HTML")) {
                if (PATTERN_HTML.matcher(new String(data)).find()) return true;
            } else {
                LOGGER.debug(
                        "Unknown file extension {}. Accepting this file type without verifying it. Could therefore be a false positive.",
                        fileExtension);
                // unknown file extension. just accept it as it is.
                return true;
            }
            // known file type, but not matched. do not accept it.
            return false;
        } else {
            // no file extension, therefore no way to verify the source code.. so accept it as it is
            return true;
        }
    }

    @Override
    public int getRisk() {
        return Alert
                .RISK_HIGH; // definitely a High. If we get the source, we don't need to hack the
        // app any more, because we can just analyse it off-line! Sweet..
    }

    @Override
    public int getCweId() {
        return 541; // Information Exposure Through Include Source Code
    }

    @Override
    public int getWascId() {
        return 33; // Path Traversal
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    /**
     * calculate the percentage length between the 2 strings.
     *
     * @param a
     * @param b
     * @return
     */
    private static int calcLengthMatchPercentage(int a, int b) {
        if (a == 0 && b == 0) return 100;
        if (a == 0 || b == 0) return 0;

        return (int) ((((double) Math.min(a, b)) / Math.max(a, b)) * 100);
    }

    private AlertBuilder createAlert(
            String paramname,
            String prefixedUrlfilename,
            Integer randomversussourcefilenamematchpercentage,
            HttpMessage sourceattackmsg,
            String uri) {
        return createAlert(
                paramname,
                prefixedUrlfilename,
                NON_EXISTANT_FILENAME,
                randomversussourcefilenamematchpercentage,
                sourceattackmsg,
                uri);
    }

    private AlertBuilder createAlert(
            String paramname,
            String prefixedUrlfilename,
            String nonExistentFilename,
            Integer randomversussourcefilenamematchpercentage,
            HttpMessage sourceattackmsg,
            String uri) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setUri(uri)
                .setParam(paramname)
                .setAttack(prefixedUrlfilename)
                .setOtherInfo(
                        Constant.messages.getString(
                                "ascanbeta.sourcecodedisclosure.lfibased.extrainfo",
                                prefixedUrlfilename,
                                nonExistentFilename,
                                randomversussourcefilenamematchpercentage,
                                this.thresholdPercentage))
                .setMessage(sourceattackmsg);
    }

    @Override
    public List<Alert> getExampleAlerts() {
        String exampleUri = "https://example.com";
        return List.of(
                createAlert(
                                "name",
                                "../config/database.php",
                                "jzdysfaeeinxxtsvjfggrwaucugjvsvpawibnv",
                                48,
                                null,
                                exampleUri)
                        .build());
    }
}
