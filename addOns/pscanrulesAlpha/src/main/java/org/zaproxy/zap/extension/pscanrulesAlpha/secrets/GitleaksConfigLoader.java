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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;
import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.pscanrulesAlpha.secrets.GitleaksAllowlist.Target;

/**
 * Loads a Gitleaks config (TOML), compiling all regexes with re2j. A rule is skipped if its regex
 * or the regex of one of its allowlists is not supported by re2j (there is no fallback to another
 * regex engine), or if it has no regex. A global allowlist pattern that is not supported is
 * ignored. All the pattern failures are collected in the returned config.
 */
public final class GitleaksConfigLoader {

    private static final Logger LOGGER = LogManager.getLogger(GitleaksConfigLoader.class);

    private GitleaksConfigLoader() {}

    /**
     * The usable content of a Gitleaks config.
     *
     * @param rules the rules whose patterns (regex and allowlists) all compiled with re2j.
     * @param failures a description of each pattern that could not be compiled (all of them are
     *     collected, not just the first), empty if the config is fully supported.
     * @param global the global allowlist.
     */
    public record Config(
            List<GitleaksRule> rules, List<String> failures, GitleaksAllowlist global) {}

    public static Config load(InputStream is) throws IOException {
        JsonNode root = new TomlMapper().readTree(is);

        List<String> failures = new ArrayList<>();
        // Patterns that fail to compile are ignored, the rest of the global allowlist is kept.
        GitleaksAllowlist global = allowlist("global allowlist", root.path("allowlist"), failures);

        List<GitleaksRule> rules = new ArrayList<>();
        for (JsonNode node : root.path("rules")) {
            String id = node.path("id").asText("");
            if (!node.hasNonNull("regex")) {
                LOGGER.debug("Skipping Gitleaks rule '{}', it has no regex.", id);
                continue;
            }
            // A rule with any pattern that fails to compile is skipped.
            List<String> ruleFailures = new ArrayList<>();
            Pattern regex = compile(id, node.get("regex").asText(), ruleFailures);
            List<GitleaksAllowlist> allowlists = new ArrayList<>();
            for (JsonNode allowlist : node.path("allowlists")) {
                allowlists.add(allowlist(id, allowlist, ruleFailures));
            }
            if (!ruleFailures.isEmpty()) {
                failures.addAll(ruleFailures);
                continue;
            }
            List<String> keywords = new ArrayList<>();
            for (JsonNode keyword : node.path("keywords")) {
                keywords.add(keyword.asText().toLowerCase(Locale.ROOT));
            }
            rules.add(
                    new GitleaksRule(
                            id,
                            node.path("description").asText(""),
                            regex,
                            node.path("secretGroup").asInt(0),
                            node.path("entropy").asDouble(0),
                            List.copyOf(keywords),
                            List.copyOf(allowlists)));
        }
        failures.forEach(failure -> LOGGER.debug("Gitleaks pattern failure: {}", failure));
        LOGGER.debug(
                "Gitleaks config loaded, {} rules active, {} patterns failed.",
                rules.size(),
                failures.size());
        return new Config(List.copyOf(rules), List.copyOf(failures), global);
    }

    private static GitleaksAllowlist allowlist(String owner, JsonNode node, List<String> failures) {
        List<Pattern> regexes = compileAll(owner, node.path("regexes"), failures);
        List<Pattern> paths = compileAll(owner, node.path("paths"), failures);
        List<String> stopwords = new ArrayList<>();
        for (JsonNode stopword : node.path("stopwords")) {
            stopwords.add(stopword.asText().toLowerCase(Locale.ROOT));
        }
        Target target =
                switch (node.path("regexTarget").asText("secret")) {
                    case "match" -> Target.MATCH;
                    case "line" -> Target.LINE;
                    default -> Target.SECRET;
                };
        return new GitleaksAllowlist(
                regexes,
                List.copyOf(stopwords),
                paths,
                target,
                "AND".equalsIgnoreCase(node.path("condition").asText("OR")));
    }

    private static List<Pattern> compileAll(String owner, JsonNode nodes, List<String> failures) {
        List<Pattern> patterns = new ArrayList<>();
        for (JsonNode node : nodes) {
            Pattern pattern = compile(owner, node.asText(), failures);
            if (pattern != null) {
                patterns.add(pattern);
            }
        }
        return List.copyOf(patterns);
    }

    private static Pattern compile(String owner, String regex, List<String> failures) {
        try {
            return Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            failures.add(owner + ": " + e.getMessage());
            return null;
        }
    }
}
