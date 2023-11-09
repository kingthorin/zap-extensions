/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class FullPathDisclosureScanRuleUnitTest extends PluginPassiveScanner {
    private final int pluginID = 110009;
    private static final String MESSAGE_PREFIX = "pscanalpha.fullpathdisclosurealert.";

    @Override
    public int getPluginId() {
        return this.pluginID;
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        final String responseBody = msg.getResponseBody().toString();
        StringBuilder evidence = new StringBuilder();
        // used to keep track of already inserted paths to avoid repetition
        Set<String> foundPaths = new HashSet<>();
        boolean patternFound = false;

        // Matches the presence of one of the default paths in the response body
        Pattern defaultPathPattern =
                Pattern.compile(
                        "(?i)/bin|/usr|/mnt|/proc|/sbin|/dev|/lib|/tmp|/opt|/home|/var|/root|/etc|\\\\Applications|\\\\Volumes|\\\\System|\\\\Users|\\\\Developer|\\\\Library");
        Matcher defaultPathMatcher = defaultPathPattern.matcher(responseBody);

        // matches the presence of either windows style or unix style full paths
        // example for windows : C:\folder\folder
        // example for unix : /dir/dir
        Pattern pathPattern =
                Pattern.compile("(?i)(/([a-z0-9]+/)+)|(([a-z0-9]:\\\\)+([a-z0-9]+\\\\)+)");
        Matcher pathMatcher = pathPattern.matcher(responseBody);

        if (getHelper().isSuccess(msg)) {
            return;
        }
        while (defaultPathMatcher.find()) {
            patternFound = true;
            String currPath = defaultPathMatcher.group();
            if (!foundPaths.contains(currPath)) {
                foundPaths.add(currPath);
                evidence.append(defaultPathMatcher.group()).append(" , ");
            }
        }
        while (pathMatcher.find()) {
            patternFound = true;
            String currPath = pathMatcher.group();
            // if the current Full path has not been seen before
            if (!foundPaths.contains(currPath)) {
                foundPaths.add(currPath);
                evidence.append(pathMatcher.group()).append(" , ");
            }
        }
        if (patternFound) {
            buildAlert(evidence.toString()).raise();
        }
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private Integer getRisk() {
        return Alert.RISK_LOW;
    }

    private Integer getConfidence() {
        return Alert.CONFIDENCE_LOW;
    }

    private String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    private AlertBuilder buildAlert(String evidence) {
        return newAlert()
                .setConfidence(getConfidence())
                .setRisk(getRisk())
                .setEvidence(evidence)
                .setDescription(getDescription())
                .setSolution(getSolution())
                .setReference(getReference())
                .setSolution(getSolution());
    }
}
