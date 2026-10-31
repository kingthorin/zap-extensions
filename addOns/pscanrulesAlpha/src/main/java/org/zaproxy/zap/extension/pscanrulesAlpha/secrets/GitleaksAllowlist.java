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
package org.zaproxy.zap.extension.pscanrulesAlpha.secrets;

import com.google.re2j.Pattern;
import java.util.List;
import java.util.Locale;

/** A Gitleaks allowlist, only the parts which apply to HTTP messages (no commits). */
public class GitleaksAllowlist {

    enum Target {
        SECRET,
        MATCH,
        LINE
    }

    private final List<Pattern> regexes;
    private final List<String> stopwords;
    private final List<Pattern> paths;
    private final Target target;
    private final boolean and;

    GitleaksAllowlist(
            List<Pattern> regexes,
            List<String> stopwords,
            List<Pattern> paths,
            Target target,
            boolean and) {
        this.regexes = regexes;
        this.stopwords = stopwords;
        this.paths = paths;
        this.target = target;
        this.and = and;
    }

    /** Tells whether the line of the finding is needed to evaluate this allowlist. */
    boolean needsLine() {
        return target == Target.LINE && !regexes.isEmpty();
    }

    /**
     * Tells whether the path alone allows (i.e. ignores) everything, which is the case when the
     * allowlist has a matching path and its condition is OR. Allows to skip scanning the body. If
     * there are no paths, or none match, the content still has to be scanned.
     */
    public boolean allowsPath(String path) {
        return path != null && !and && !paths.isEmpty() && anyMatch(paths, path);
    }

    /**
     * Tells whether the given finding is allowed.
     *
     * @param line the line of the finding, only needed if {@link #needsLine()}.
     * @param path the path of the request, {@code null} to not take the path criteria into account.
     */
    boolean allows(String match, String secret, String line, String path) {
        boolean checkPath = path != null && !paths.isEmpty();
        boolean regexHit = !regexes.isEmpty() && anyMatch(regexes, target(match, secret, line));
        boolean stopHit = !stopwords.isEmpty() && matchesStopword(secret);
        boolean pathHit = checkPath && anyMatch(paths, path);
        if (!and) {
            return regexHit || stopHit || pathHit;
        }
        boolean hasCriteria = !regexes.isEmpty() || !stopwords.isEmpty() || checkPath;
        return hasCriteria
                && (regexes.isEmpty() || regexHit)
                && (stopwords.isEmpty() || stopHit)
                && (!checkPath || pathHit);
    }

    private String target(String match, String secret, String line) {
        return switch (target) {
            case MATCH -> match;
            case LINE -> line;
            case SECRET -> secret;
        };
    }

    private static boolean anyMatch(List<Pattern> patterns, String text) {
        return patterns.stream().anyMatch(pattern -> pattern.matcher(text).find());
    }

    private boolean matchesStopword(String secret) {
        String lower = secret.toLowerCase(Locale.ROOT);
        return stopwords.stream().anyMatch(lower::contains);
    }
}
