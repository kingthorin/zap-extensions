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

import com.google.re2j.Matcher;
import com.google.re2j.Pattern;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * A Gitleaks rule with its regex compiled using re2j.
 *
 * <p>Maps the fields of a Gitleaks {@code [[rules]]} entry, only those that apply to HTTP messages
 * (path and commit based features are not used). The steps, in order:
 *
 * <ol>
 *   <li>Rule allowlist paths: if the request path matches the paths of one of the allowlists of
 *       this rule (see {@link GitleaksAllowlist#allowsPath}) the rule is not run, allowlists hold
 *       what to ignore. The paths of the global allowlist are checked earlier, before any rule is
 *       run.
 *   <li>{@code keywords}: cheap pre-filter, the rule is not run unless the content contains at
 *       least one of them (ignoring case). Rules without keywords always run.
 *   <li>{@code regex}: the regex pattern used to match within the content, each match is a
 *       candidate finding that goes through the remaining steps. Many regexes are slow on large
 *       content, because they start with a prefix that can match anywhere (e.g. {@code
 *       [\w.-]{0,50}?}). When the width of a match can be estimated, see {@link #windowRadius}, the
 *       regex is only run on the windows around the keywords, a match has to contain a keyword, as
 *       Gitleaks requires for its rules. The other regexes are run on all the content.
 *   <li>{@code entropy}: the secret needs at least that Shannon entropy, to discard placeholders.
 *       The secret is the {@code secretGroup} capture group if set, otherwise the first non-empty
 *       capture group, otherwise the whole match.
 *   <li>Allowlists: the global allowlist and the rule {@code allowlists}, which hold what to
 *       ignore, see {@link GitleaksAllowlist}. A match is ignored (and the next one tried) if it
 *       matches the allowlist regexes or if the secret contains one of its stopwords (e.g. {@code
 *       example}, ignoring case). By default any one of these is enough, with {@code condition =
 *       "AND"} all of them are needed, and then, at High threshold, the request path matching the
 *       allowlist paths is one of the criteria too.
 * </ol>
 *
 * The first candidate that survives the remaining steps is the finding.
 */
public class GitleaksRule {

    /** A secret found in a body. */
    public record Finding(String ruleId, String description, String match, String secret) {}

    /** The assumed maximum length of an unbounded run of characters, see {@link #windowRadius}. */
    private static final int UNBOUNDED_RUN = 1024;

    private static final int MAX_WINDOW_RADIUS = 4096;

    private final String id;
    private final String description;
    private final Pattern regex;
    private final int secretGroup;
    private final double entropy;
    private final List<String> keywords;
    private final List<GitleaksAllowlist> allowlists;
    private final boolean needsLine;

    /** The size of the windows around the keywords where the regex is run, 0 for all content. */
    private final int windowRadius;

    GitleaksRule(
            String id,
            String description,
            Pattern regex,
            int secretGroup,
            double entropy,
            List<String> keywords,
            List<GitleaksAllowlist> allowlists) {
        this.id = id;
        this.description = description;
        this.regex = regex;
        this.secretGroup = secretGroup;
        this.entropy = entropy;
        this.keywords = keywords;
        this.allowlists = allowlists;
        this.needsLine = allowlists.stream().anyMatch(GitleaksAllowlist::needsLine);
        this.windowRadius = keywords.isEmpty() ? 0 : windowRadius(regex.pattern());
    }

    public String getId() {
        return id;
    }

    // Visible for testing.
    boolean isWindowed() {
        return windowRadius > 0;
    }

    /**
     * Gets the width of the windows around the keywords, where the regex is run, it is an over
     * estimation of the width of a match, without parsing the regex: each character counts as 1 (a
     * class or an escape as a whole), plus the maximum of each repetition.
     *
     * <p>The patterns are not modified. An unbounded repetition ({@code *}, {@code +}, {@code
     * {n,}}) of a single character or class, e.g. the body of a token, counts as {@value
     * #UNBOUNDED_RUN}, which is an assumption about the longest such run. A match which runs longer
     * is cut by the window, and is not reported (see {@link #find}).
     *
     * @return the width, or {@code 0} if it can't be estimated: unbounded or repeated groups, an
     *     unbounded {@code .} or too wide.
     */
    static int windowRadius(String regex) {
        int width = 0;
        // Whether the last atom is a group or a dot, which can't be repeated without bounds.
        boolean groupOrDot = false;
        for (int i = 0; i < regex.length(); i++) {
            char c = regex.charAt(i);
            width++;
            if (c == '\\') {
                i++;
                groupOrDot = false;
            } else if (c == '[') {
                // Skip the class, it is a single character.
                for (i++; i < regex.length() && regex.charAt(i) != ']'; i++) {
                    if (regex.charAt(i) == '\\') {
                        i++;
                    }
                }
                groupOrDot = false;
            } else if (c == '*' || c == '+') {
                if (groupOrDot) {
                    return 0;
                }
                width += UNBOUNDED_RUN;
            } else if (c == '{') {
                int end = regex.indexOf('}', i);
                String[] range = regex.substring(i + 1, end).split(",", -1);
                String max = range[range.length - 1];
                if (max.isEmpty()) {
                    if (groupOrDot) {
                        return 0;
                    }
                    width += UNBOUNDED_RUN;
                } else {
                    if (regex.charAt(i - 1) == ')') {
                        return 0;
                    }
                    width += Integer.parseInt(max);
                }
                i = end;
            } else if (c == ')' || c == '.') {
                groupOrDot = true;
            } else if (c != '?') {
                groupOrDot = false;
            }
        }
        return width > MAX_WINDOW_RADIUS ? 0 : width;
    }

    /**
     * Finds the first secret in the given body which is not allowed.
     *
     * @param body the body to search.
     * @param lowerCaseBody the body in lower case, which has to be of the same length (e.g. not
     *     String#toLowerCase), used for the keywords pre-filter and the windows.
     * @param global the global allowlist.
     * @param path the path of the request, used by the allowlists paths, {@code null} to ignore
     *     them.
     */
    public Optional<Finding> find(
            String body, String lowerCaseBody, GitleaksAllowlist global, String path) {
        if (allowlists.stream().anyMatch(allowlist -> allowlist.allowsPath(path))) {
            return Optional.empty();
        }
        if (!keywords.isEmpty() && keywords.stream().noneMatch(lowerCaseBody::contains)) {
            return Optional.empty();
        }
        if (windowRadius == 0) {
            return find(body, 0, body, global, path);
        }
        BitSet windows = new BitSet(body.length());
        for (String keyword : keywords) {
            for (int i = lowerCaseBody.indexOf(keyword);
                    i >= 0;
                    i = lowerCaseBody.indexOf(keyword, i + 1)) {
                windows.set(
                        Math.max(0, i - windowRadius),
                        Math.min(body.length(), i + keyword.length() + windowRadius));
            }
        }
        for (int from = windows.nextSetBit(0); from >= 0; ) {
            int to = windows.nextClearBit(from);
            Optional<Finding> finding = find(body.substring(from, to), from, body, global, path);
            if (finding.isPresent()) {
                return finding;
            }
            from = windows.nextSetBit(to);
        }
        return Optional.empty();
    }

    /**
     * Finds the first secret in the given text which is not allowed.
     *
     * @param text the text to search, the body or a window of it.
     * @param offset the offset of the text in the body.
     */
    private Optional<Finding> find(
            String text, int offset, String body, GitleaksAllowlist global, String path) {
        Matcher matcher = regex.matcher(text);
        while (matcher.find()) {
            // A match at an edge of a window, which is not the start or the end of the body, may
            // have been cut by the window (or got a false word boundary or end of text), skip it.
            if ((offset > 0 && matcher.start() == 0)
                    || (offset + text.length() < body.length() && matcher.end() == text.length())) {
                continue;
            }
            String match = matcher.group();
            if (windowRadius > 0 && !containsKeyword(match)) {
                continue;
            }
            String secret = secret(matcher);
            if (entropy > 0 && shannonEntropy(secret) < entropy) {
                continue;
            }
            // The line can be huge (e.g. minified JS), only get it when an allowlist needs it.
            String line =
                    needsLine || global.needsLine()
                            ? line(body, offset + matcher.start(), offset + matcher.end())
                            : null;
            boolean allowed = global.allows(match, secret, line, path);
            for (int i = 0; !allowed && i < allowlists.size(); i++) {
                allowed = allowlists.get(i).allows(match, secret, line, path);
            }
            if (!allowed) {
                return Optional.of(new Finding(id, description, match, secret));
            }
        }
        return Optional.empty();
    }

    private boolean containsKeyword(String match) {
        String lowerCaseMatch = match.toLowerCase(Locale.ROOT);
        return keywords.stream().anyMatch(lowerCaseMatch::contains);
    }

    private String secret(Matcher matcher) {
        if (secretGroup > 0 && secretGroup <= matcher.groupCount()) {
            String group = matcher.group(secretGroup);
            return group != null ? group : matcher.group();
        }
        for (int i = 1; i <= matcher.groupCount(); i++) {
            String group = matcher.group(i);
            if (group != null && !group.isEmpty()) {
                return group;
            }
        }
        return matcher.group();
    }

    /**
     * Gets the line of the body which contains the given match.
     *
     * <p>Used by the allowlists that have {@code regexTarget = "line"}, which check the whole line
     * rather than just the match or the secret (for example, to allow a secret on a line that is a
     * template placeholder or an import statement). Lines are delimited by {@code \n}, as Gitleaks
     * does; with CRLF line endings the line keeps a trailing {@code \r}.
     *
     * @param body the body being scanned.
     * @param start the start offset of the match.
     * @param end the end offset of the match.
     * @return the line, without the line terminator.
     */
    private static String line(String body, int start, int end) {
        int from = body.lastIndexOf('\n', start - 1) + 1;
        int to = body.indexOf('\n', end);
        return body.substring(from, to < 0 ? body.length() : to);
    }

    static double shannonEntropy(String value) {
        if (value.isEmpty()) {
            return 0;
        }
        char[] chars = value.toCharArray();
        Arrays.sort(chars);
        double entropy = 0;
        int count = 0;
        for (int i = 0; i < chars.length; i++) {
            count++;
            if (i + 1 == chars.length || chars[i + 1] != chars[i]) {
                double p = (double) count / chars.length;
                entropy -= p * Math.log(p) / Math.log(2);
                count = 0;
            }
        }
        return entropy;
    }
}
