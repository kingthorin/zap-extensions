/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2011 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import static org.zaproxy.zap.extension.ascanrules.utils.Constants.NULL_BYTE_CHARACTER;

import java.io.IOException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.addon.network.common.ZapSocketTimeoutException;
import org.zaproxy.zap.model.Tech;

/** A scan rule that looks for Path Traversal vulnerabilities. */
public class PathTraversalScanRule extends AbstractAppParamPlugin
        implements CommonActiveScanRuleInfo {

    /*
     * Prefix for internationalised messages used by this rule
     */
    private static final String MESSAGE_PREFIX = "ascanrules.pathtraversal.";

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
                                CommonAlertTag.OWASP_2017_A05_BROKEN_AC,
                                CommonAlertTag.WSTG_V42_ATHZ_01_DIR_TRAVERSAL,
                                CommonAlertTag.HIPAA,
                                CommonAlertTag.PCI_DSS));
        alertTags.put(PolicyTag.DEV_STD.getTag(), "");
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.SEQUENCE.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private static final String NON_EXISTANT_FILENAME = "thishouldnotexistandhopefullyitwillnot";

    /*
     * Windows local file targets and detection pattern
     */
    private static final ContentsMatcher WIN_PATTERN =
            new PatternContentsMatcher(Pattern.compile("\\[drivers\\]"));
    private static final String[] WIN_LOCAL_FILE_TARGETS = {
        // Absolute Windows file retrieval (we suppose C:\\)
        "c:/Windows/system.ini",
        "../../../../../../../../../../../../../../../../Windows/system.ini",
        // Path traversal intended to obtain the filesystem's root
        "c:\\Windows\\system.ini",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\system.ini",
        "/../../../../../../../../../../../../../../../../Windows/system.ini",
        "\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\system.ini",
        "Windows/system.ini",
        "Windows\\system.ini",
        // From Wikipedia (http://en.wikipedia.org/wiki/File_URI_scheme)
        // file://host/path
        // If host is omitted, it is taken to be "localhost", the machine from
        // which the URL is being interpreted. Note that when omitting host you
        // do not omit the slash
        "file:///c:/Windows/system.ini",
        "file:///c:\\Windows\\system.ini",
        "file:\\\\\\c:\\Windows\\system.ini",
        "file:\\\\\\c:/Windows/system.ini",
        // "fiLe:///c:\\Windows\\system.ini",
        // "FILE:///c:\\Windows\\system.ini",
        // "fiLe:///c:/Windows/system.ini",
        // "FILE:///c:/Windows/system.ini",
        // Absolute Windows file retrieval in case of D:\\ installation dir
        "d:\\Windows\\system.ini",
        "d:/Windows/system.ini",
        "file:///d:/Windows/system.ini",
        "file:///d:\\Windows\\system.ini",
        "file:\\\\\\d:\\Windows\\system.ini",
        "file:\\\\\\d:/Windows/system.ini"
        // "E:\\Windows\\system.ini",
        // "E:/Windows/system.ini",
        // "file:///E:\\Windows\\system.ini",
        // "file:///E:/Windows/system.ini",
        // "file:\\\\\\E:\\Windows\\system.ini",
        // "file:\\\\\\E:Windows/system.ini"
        // Other LFI ideas (for future expansions)
        // ..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../boot.ini
        /// %2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/boot.ini
        // %25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..% 25%5c..%25%5c..%255cboot.ini
    };

    /*
     * Unix/Linux/etc. local file targets and detection pattern
     */
    // Dot used to match 'x' or '!' (used in AIX)
    private static final ContentsMatcher NIX_PATTERN =
            new PatternContentsMatcher(Pattern.compile("root:.:0:0"));
    private static final String[] NIX_LOCAL_FILE_TARGETS = {
        // Absolute file retrieval
        "/etc/passwd",
        // Path traversal intended to obtain the filesystem's root
        "../../../../../../../../../../../../../../../../etc/passwd",
        "/../../../../../../../../../../../../../../../../etc/passwd",
        "etc/passwd",
        // From Wikipedia (http://en.wikipedia.org/wiki/File_URI_scheme)
        // file://host/path
        // If host is omitted, it is taken to be "localhost", the machine from
        // which the URL is being interpreted. Note that when omitting host you
        // do not omit the slash
        "file:///etc/passwd",
        "file:\\\\\\etc/passwd"
        // "fiLe:///etc/passwd",
        // "FILE:///etc/passwd",
        // Other LFI ideas (for future expansions)
        // "....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd",
        // "../..//../..//../..//../..//../..//../..//../..//../..//etc/passwd",
        // "../.../.././../.../.././../.../.././../.../.././../.../.././../.../.././etc/passwd"
        // ..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd
        // ..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%00.jpg
        // ..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%2500.jpg
    };

    /*
     * Windows/Unix/Linux/etc. local directory targets and detection pattern
     */
    private static final ContentsMatcher DIR_PATTERN = new DirNamesContentsMatcher();
    private static final String[] WIN_LOCAL_DIR_TARGETS = {
        "c:/",
        "c:\\",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\",
        "\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\",
        "file:///c:/",
        "file:///c:\\",
        "file:\\\\\\c:\\",
        "file:\\\\\\c:/",
        "file:\\\\\\",
        "d:\\",
        "d:/",
        "file:///d:/",
        "file:///d:\\",
        "file:\\\\\\d:\\",
        "file:\\\\\\d:/"
    };
    private static final String[] NIX_LOCAL_DIR_TARGETS = {
        "/",
        "../../../../../../../../../../../../../../../../",
        "/../../../../../../../../../../../../../../../../",
        "file:///",
    };

    private static final ContentsMatcher WAR_PATTERN =
            new PatternContentsMatcher(Pattern.compile("</web-app>"));

    /*
     * Standard local file prefixes
     */
    private static final String[] LOCAL_FILE_RELATIVE_PREFIXES = {"", "/", "\\"};

    /*
     * details of the vulnerability which we are attempting to find
     */
    private static final Vulnerability VULN = Vulnerabilities.getDefault().get("wasc_33");

    private static final Logger LOGGER = LogManager.getLogger(PathTraversalScanRule.class);

    @Override
    public int getId() {
        return 6;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return VULN.getDescription();
    }

    @Override
    public int getCategory() {
        return Category.SERVER;
    }

    @Override
    public String getSolution() {
        return VULN.getSolution();
    }

    @Override
    public String getReference() {
        return VULN.getReferencesAsString();
    }

    /**
     * <strong>NOTE:</strong> If the checks are re-ordered please do not change the "check #"
     * identifiers. These help with troubleshooting and are included in alert Other Info.
     */
    @Override
    public void scan(HttpMessage msg, String param, String value) {

        try {
            // figure out how aggressively we should test
            int nixCount = 0;
            int winCount = 0;
            int nixDirCount = 0;
            int winDirCount = 0;
            int localTraversalLength = 0;
            String extension = null;
            boolean includeNullByteInjectionPayload = false;
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Attacking at Attack Strength: {}", this.getAttackStrength());
            }

            switch (this.getAttackStrength()) {
                case LOW:
                    // This works out as a total of 2+2+1+1+0*4+1 = 7 reqs / param
                    nixCount = 2;
                    winCount = 2;
                    nixDirCount = 1;
                    winDirCount = 1;
                    break;

                case MEDIUM:
                    // This works out as a total of 2+4+2+2+1*4+1 = 15 reqs / param
                    nixCount = 2;
                    winCount = 4;
                    nixDirCount = 2;
                    winDirCount = 2;
                    localTraversalLength = 1;
                    break;

                case HIGH:
                    // This works out as a total of 4+8+3+4+2*4+1 = 28 reqs / param
                    nixCount = 4;
                    winCount = 8;
                    nixDirCount = 3;
                    winDirCount = 4;
                    localTraversalLength = 2;
                    break;

                case INSANE:
                    // This works out as a total of 6+18+15+4+4*4+1 = 60 reqs / param
                    nixCount = NIX_LOCAL_FILE_TARGETS.length;
                    winCount = WIN_LOCAL_FILE_TARGETS.length;
                    nixDirCount = NIX_LOCAL_DIR_TARGETS.length;
                    winDirCount = WIN_LOCAL_DIR_TARGETS.length;
                    localTraversalLength = 4;
                    includeNullByteInjectionPayload = true;
                    if (value != null) {
                        int index = value.lastIndexOf(".");
                        if (index != -1) {
                            extension = value.substring(index);
                        }
                    }
                    break;

                default:
                    // Default to off
            }

            LOGGER.debug(
                    "Checking [{}] [{}], parameter [{}] for Path Traversal to local files",
                    getBaseMsg().getRequestHeader().getMethod(),
                    getBaseMsg().getRequestHeader().getURI(),
                    param);

            // Check 1: Start detection for Windows patterns
            if (inScope(Tech.Windows)) {

                for (int h = 0; h < winCount; h++) {

                    if (sendAndCheckPayload(param, WIN_LOCAL_FILE_TARGETS[h], WIN_PATTERN, 1)
                            || isStop()) {
                        // Dispose all resources
                        // Exit the scan rule
                        return;
                    }
                    // Null Byte is appended to the value for ignoring the postfix data appended
                    // to the input.
                    if (includeNullByteInjectionPayload) {
                        if (sendAndCheckPayload(
                                        param,
                                        WIN_LOCAL_FILE_TARGETS[h] + NULL_BYTE_CHARACTER,
                                        WIN_PATTERN,
                                        1)
                                || isStop()) {
                            return;
                        }
                        if (extension != null) {
                            if (sendAndCheckPayload(
                                            param,
                                            WIN_LOCAL_FILE_TARGETS[h]
                                                    + NULL_BYTE_CHARACTER
                                                    + extension,
                                            WIN_PATTERN,
                                            1)
                                    || isStop()) {
                                return;
                            }
                        }
                    }
                }
            }

            // Check 2: Start detection for *NIX patterns
            if (inScope(Tech.Linux) || inScope(Tech.MacOS)) {

                for (int h = 0; h < nixCount; h++) {

                    // Check if a there was a finding or the scan has been stopped
                    // if yes dispose resources and exit
                    if (sendAndCheckPayload(param, NIX_LOCAL_FILE_TARGETS[h], NIX_PATTERN, 2)
                            || isStop()) {
                        // Dispose all resources
                        // Exit the scan rule
                        return;
                    }
                    // Null Byte is appended to the value for ignoring the postfix data appended
                    // to the input
                    if (includeNullByteInjectionPayload) {
                        if (sendAndCheckPayload(
                                        param,
                                        NIX_LOCAL_FILE_TARGETS[h] + NULL_BYTE_CHARACTER,
                                        NIX_PATTERN,
                                        2)
                                || isStop()) {
                            return;
                        }

                        if (extension != null) {
                            if (sendAndCheckPayload(
                                            param,
                                            NIX_LOCAL_FILE_TARGETS[h]
                                                    + NULL_BYTE_CHARACTER
                                                    + extension,
                                            NIX_PATTERN,
                                            2)
                                    || isStop()) {
                                return;
                            }
                        }
                    }
                }
            }

            // Check 3: Detect if this page is a directory browsing component
            if (inScope(Tech.Linux) || inScope(Tech.MacOS)) {
                for (int h = 0; h < nixDirCount; h++) {

                    // Check if a there was a finding or the scan has been stopped
                    // if yes dispose resources and exit
                    if (sendAndCheckPayload(param, NIX_LOCAL_DIR_TARGETS[h], DIR_PATTERN, 3)
                            || isStop()) {
                        // Dispose all resources
                        // Exit the scan rule
                        return;
                    }
                }
            }
            if (inScope(Tech.Windows)) {
                for (int h = 0; h < winDirCount; h++) {
                    if (sendAndCheckPayload(param, WIN_LOCAL_DIR_TARGETS[h], DIR_PATTERN, 3)
                            || isStop()) {
                        // Dispose all resources
                        // Exit the scan rule
                        return;
                    }
                }
            }
            // Check 4: Start detection for internal well known files
            // try variants based on increasing ../ ..\ prefixes and the presence of the / and \
            // trailer
            // e.g. WEB-INF/web.xml, /WEB-INF/web.xml, ../WEB-INF/web.xml, /../WEB-INF/web.xml, ecc.
            // Both slashed and backslashed variants are checked
            // -------------------------------
            // Currently we've always checked only for J2EE known files
            // and this remains also for this version
            //
            // Web.config for .NET in the future?
            // -------------------------------
            String sslashPattern = "WEB-INF/web.xml";
            // The backslashed version of the same check
            String bslashPattern = sslashPattern.replace('/', '\\');

            if (inScope(Tech.Tomcat)) {

                for (int idx = 0; idx < localTraversalLength; idx++) {

                    if (sendAndCheckPayload(param, sslashPattern, WAR_PATTERN, 4)
                            || sendAndCheckPayload(param, bslashPattern, WAR_PATTERN, 4)
                            || sendAndCheckPayload(param, '/' + sslashPattern, WAR_PATTERN, 4)
                            || sendAndCheckPayload(param, '\\' + bslashPattern, WAR_PATTERN, 4)
                            || isStop()) {

                        // Dispose all resources
                        // Exit the scan rule
                        return;
                    }

                    sslashPattern = "../" + sslashPattern;
                    bslashPattern = "..\\" + bslashPattern;
                }
            }

            if (getAlertThreshold().equals(AlertThreshold.LOW)
                    || getAlertThreshold().equals(AlertThreshold.MEDIUM)) {
                // Check 5: try a local file Path Traversal on the file name of the URL (which
                // obviously will not be in the target list above).
                // first send a query for a random parameter value, and see if we get a 200 back
                // if 200 is returned, abort this check (on the url filename itself), because it
                // would be unreliable.
                // if we know that a random query returns <> 200, then a 200 response likely means
                // something!
                // this logic is all about avoiding false positives, while still attempting to match
                // on actual vulnerabilities
                msg = getNewMsg();
                setParameter(msg, param, NON_EXISTANT_FILENAME);

                // send the modified message (with a hopefully non-existent filename), and see what
                // we get back
                try {
                    sendAndReceive(msg);

                } catch (SocketException
                        | IllegalStateException
                        | UnknownHostException
                        | IllegalArgumentException
                        | URIException ex) {
                    LOGGER.debug(
                            "Caught {} {} when accessing: {}",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            msg.getRequestHeader().getURI());

                    return; // Something went wrong, no point continuing
                }

                // do some pattern matching on the results.
                Pattern errorPattern = Pattern.compile("Exception|Error", Pattern.CASE_INSENSITIVE);
                Matcher errorMatcher = errorPattern.matcher(msg.getResponseBody().toString());

                String urlfilename = msg.getRequestHeader().getURI().getName();

                // url file name may be empty, i.e. there is no file name for next check
                if (!StringUtils.isEmpty(urlfilename) && (!isPage200(msg) || errorMatcher.find())) {

                    LOGGER.debug(
                            "It is possible to check for local file Path Traversal on the url filename on [{}] [{}], [{}]",
                            msg.getRequestHeader().getMethod(),
                            msg.getRequestHeader().getURI(),
                            param);

                    String prefixedUrlfilename;

                    // for the url filename, try each of the prefixes in turn
                    for (String prefix : LOCAL_FILE_RELATIVE_PREFIXES) {
                        if (isStop()) {
                            return;
                        }

                        prefixedUrlfilename = prefix + urlfilename;
                        msg = getNewMsg();
                        setParameter(msg, param, prefixedUrlfilename);

                        // send the modified message (with the url filename), and see what we get
                        // back
                        try {
                            sendAndReceive(msg);

                        } catch (SocketException
                                | IllegalStateException
                                | UnknownHostException
                                | IllegalArgumentException
                                | URIException ex) {
                            LOGGER.debug(
                                    "Caught {} {} when accessing: {}",
                                    ex.getClass().getName(),
                                    ex.getMessage(),
                                    msg.getRequestHeader().getURI());

                            continue; // Something went wrong, move to the next prefix in the loop
                        }

                        // did we get an Exception or an Error?
                        errorMatcher = errorPattern.matcher(msg.getResponseBody().toString());
                        if (isPage200(msg) && (!errorMatcher.find())) {

                            // if it returns OK, and the random string above did NOT return ok, then
                            // raise an alert since the filename has likely been picked up and used
                            // as a file name from the parameter
                            createUnmatchedAlert(param, prefixedUrlfilename)
                                    .setMessage(msg)
                                    .raise();

                            // All done. No need to look for vulnerabilities on subsequent
                            // parameters on the same request (to reduce performance impact)
                            return;
                        }
                    }
                }
            }

            // Check 6 for local file names
            // TODO: consider making this check 1, for performance reasons
            // TODO: if the original query was http://www.example.com/a/b/c/d.jsp?param=paramvalue
            // then check if the following gives comparable results to the original query
            // http://www.example.com/a/b/c/d.jsp?param=../c/paramvalue
            // if it does, then we likely have a local file Path Traversal vulnerability
            // this is nice because it means we do not have to guess any file names, and would only
            // require one
            // request to find the vulnerability
            // but it would be foiled by simple input validation on "..", for instance.

        } catch (ZapSocketTimeoutException ste) {
            LOGGER.warn(
                    "A timeout occurred while checking [{}] [{}], parameter [{}] for Path Traversal. The currently configured timeout is: {}",
                    msg.getRequestHeader().getMethod(),
                    msg.getRequestHeader().getURI(),
                    param,
                    ste.getTimeout());

            LOGGER.debug("Caught {} {}", ste.getClass().getName(), ste.getMessage());

        } catch (IOException e) {
            LOGGER.warn(
                    "An error occurred while checking [{}] [{}], parameter [{}] for Path Traversal.Caught {} {}",
                    msg.getRequestHeader().getMethod(),
                    msg.getRequestHeader().getURI(),
                    param,
                    e.getClass().getName(),
                    e.getMessage());
        }
    }

    private boolean sendAndCheckPayload(
            String param, String newValue, ContentsMatcher contentsMatcher, int check)
            throws IOException {
        if (contentsMatcher.match(getContentsToMatch(getBaseMsg())) != null) {
            // Evidence already present, no point sending the payload/attack.
            return false;
        }

        // get a new copy of the original message (request only)
        // and set the specific pattern
        HttpMessage msg = getNewMsg();
        setParameter(msg, param, newValue);

        LOGGER.debug(
                "Checking [{}] [{}], parameter [{}] for Windows Path Traversal (local file) with value [{}]",
                msg.getRequestHeader().getMethod(),
                msg.getRequestHeader().getURI(),
                param,
                newValue);

        // send the modified request, and see what we get back
        try {
            sendAndReceive(msg);

        } catch (SocketException
                | IllegalStateException
                | UnknownHostException
                | IllegalArgumentException
                | URIException ex) {
            LOGGER.debug(
                    "Caught {} {} when accessing: {}",
                    ex.getClass().getName(),
                    ex.getMessage(),
                    msg.getRequestHeader().getURI());

            return false; // Something went wrong, no point continuing
        }

        // does it match the pattern specified for that file name?
        String match = contentsMatcher.match(getContentsToMatch(msg));

        // if the output matches, and we get a 200
        if (isPage200(msg) && match != null) {
            createMatchedAlert(param, newValue, match, check).setMessage(msg).raise();

            // All done. No need to look for vulnerabilities on subsequent parameters
            // on the same request (to reduce performance impact)
            return true;
        }

        return false;
    }

    private static String getContentsToMatch(HttpMessage message) {
        return message.getResponseHeader().isHtml()
                ? StringEscapeUtils.unescapeHtml4(message.getResponseBody().toString())
                : message.getResponseHeader().toString() + message.getResponseBody().toString();
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getCweId() {
        return 22;
    }

    @Override
    public int getWascId() {
        return 33;
    }

    private AlertBuilder createUnmatchedAlert(String param, String attack) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setParam(param)
                .setAttack(attack)
                .setAlertRef(getId() + "-" + 5);
    }

    private AlertBuilder createMatchedAlert(
            String param, String attack, String evidence, int check) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setParam(param)
                .setAttack(attack)
                .setEvidence(evidence)
                .setAlertRef(getId() + "-" + check);
    }

    @Override
    public List<Alert> getExampleAlerts() {
        String param = "query";
        List<Alert> list = new ArrayList<>(5);
        list.add(
                createMatchedAlert(param, "file:///c:/Windows/system.ini", "\\[drivers\\]", 1)
                        .build());
        list.add(createMatchedAlert(param, "/etc/passwd", "root:.:0:0", 2).build());
        list.add(createMatchedAlert(param, "c:\\", "Program\\sFiles", 3).build());
        list.add(createMatchedAlert(param, "WEB-INF/web.xml", "</web-app>", 4).build());
        list.add(createUnmatchedAlert(param, "C:/").build());
        return list;
    }

    private interface ContentsMatcher {

        String match(String contents);
    }

    private static class PatternContentsMatcher implements ContentsMatcher {

        private final Pattern pattern;

        public PatternContentsMatcher(Pattern pattern) {
            this.pattern = pattern;
        }

        @Override
        public String match(String contents) {
            Matcher matcher = pattern.matcher(contents);
            if (matcher.find()) {
                return matcher.group();
            }
            return null;
        }
    }

    private static class DirNamesContentsMatcher implements ContentsMatcher {

        @Override
        public String match(String contents) {
            String result = matchNixDirectories(contents);
            if (result != null) {
                return result;
            }
            return matchWinDirectories(contents);
        }

        private static String matchNixDirectories(String contents) {
            Pattern procPattern =
                    Pattern.compile("(?:^|\\W)proc(?:\\W|$)", Pattern.CASE_INSENSITIVE);
            Pattern etcPattern = Pattern.compile("(?:^|\\W)etc(?:\\W|$)", Pattern.CASE_INSENSITIVE);
            Pattern bootPattern =
                    Pattern.compile("(?:^|\\W)boot(?:\\W|$)", Pattern.CASE_INSENSITIVE);
            Pattern tmpPattern = Pattern.compile("(?:^|\\W)tmp(?:\\W|$)", Pattern.CASE_INSENSITIVE);
            Pattern homePattern =
                    Pattern.compile("(?:^|\\W)home(?:\\W|$)", Pattern.CASE_INSENSITIVE);

            Matcher procMatcher = procPattern.matcher(contents);
            Matcher etcMatcher = etcPattern.matcher(contents);
            Matcher bootMatcher = bootPattern.matcher(contents);
            Matcher tmpMatcher = tmpPattern.matcher(contents);
            Matcher homeMatcher = homePattern.matcher(contents);

            if (procMatcher.find()
                    && etcMatcher.find()
                    && bootMatcher.find()
                    && tmpMatcher.find()
                    && homeMatcher.find()) {
                return "etc";
            }

            return null;
        }

        private static String matchWinDirectories(String contents) {
            if (contents.contains("Windows")
                    && Pattern.compile("Program\\sFiles").matcher(contents).find()) {
                return "Windows";
            }

            return null;
        }
    }
}
