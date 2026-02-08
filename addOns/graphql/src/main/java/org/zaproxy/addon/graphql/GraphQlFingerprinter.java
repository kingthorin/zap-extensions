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
package org.zaproxy.addon.graphql;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

public class GraphQlFingerprinter {

    private static final String FINGERPRINTING_ALERT_REF = ExtensionGraphQl.TOOL_ALERT_ID + "-2";
    private static final Map<String, String> FINGERPRINTING_ALERT_TAGS =
            CommonAlertTag.toMap(CommonAlertTag.WSTG_V42_INFO_02_FINGERPRINT_WEB_SERVER);
    private static final Logger LOGGER = LogManager.getLogger(GraphQlFingerprinter.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static List<DiscoveredGraphQlEngineHandler> handlers;

    private final URI endpointUrl;
    private final Requestor requestor;
    private final Map<String, HttpMessage> queryCache;

    private HttpMessage lastQueryMsg;
    private HttpMessage matchedMessage;
    private String matchedString;

    public GraphQlFingerprinter(URI endpointUrl, Requestor requestor) {
        resetHandlers();
        this.endpointUrl = endpointUrl;
        this.requestor = requestor;
        queryCache = new HashMap<>();
    }

    public void fingerprint() {
        Map<String, BooleanSupplier> fingerprinters = new LinkedHashMap<>();
        // TODO: Check whether the order of the fingerprint checks matters.
        fingerprinters.put("lighthouse", this::checkLighthouseEngine);
        fingerprinters.put("caliban", this::checkCalibanEngine);
        fingerprinters.put("lacinia", this::checkLaciniaEngine);
        fingerprinters.put("jaal", this::checkJaalEngine);
        fingerprinters.put("morpheus", this::checkMorpheusEngine);
        fingerprinters.put("mercurius", this::checkMercuriusEngine);
        fingerprinters.put("graphql-yoga", this::checkGraphQlYogaEngine);
        fingerprinters.put("agoo", this::checkAgooEngine);
        fingerprinters.put("dgraph", this::checkDgraphEngine);
        fingerprinters.put("graphene", this::checkGrapheneEngine);
        fingerprinters.put("ariadne", this::checkAriadneEngine);
        fingerprinters.put("apollo", this::checkApolloEngine);
        fingerprinters.put("aws-appsync", this::checkAwsAppSyncEngine);
        fingerprinters.put("hasura", this::checkHasuraEngine);
        fingerprinters.put("wpgraphql", this::checkWpGraphQlEngine);
        fingerprinters.put("graphql-by-pop", this::checkGraphQlByPopEngine);
        fingerprinters.put("graphql-java", this::checkGraphQlJavaEngine);
        fingerprinters.put("hypergraphql", this::checkHyperGraphQlEngine);
        fingerprinters.put("graphql-ruby", this::checkGraphQlRubyEngine);
        fingerprinters.put("graphql-php", this::checkGraphQlPhpEngine);
        fingerprinters.put("gqlgen", this::checkGqlGenEngine);
        fingerprinters.put("graphql-go", this::checkGraphQlGoEngine);
        fingerprinters.put("juniper", this::checkJuniperEngine);
        fingerprinters.put("sangria", this::checkSangriaEngine);
        fingerprinters.put("graphql-flutter", this::checkFlutterEngine);
        fingerprinters.put("dianajl", this::checkDianajlEngine);
        fingerprinters.put("strawberry", this::checkStrawberryEngine);
        fingerprinters.put("tartiflette", this::checkTartifletteEngine);
        fingerprinters.put("directus", this::checkDirectusEngine);
        fingerprinters.put("absinthe", this::checkAbsintheEngine);
        fingerprinters.put("graphql-dotnet", this::checkGraphqlDotNetEngine);
        fingerprinters.put("pg_graphql", this::checkPgGraphqlEngine);
        fingerprinters.put("tailcall", this::checkTailcallEngine);
        fingerprinters.put("hotchocolate", this::checkHotchocolateEngine);
        fingerprinters.put("inigo", this::checkInigoEngine);

        for (var fingerprinter : fingerprinters.entrySet()) {
            try {
                if (fingerprinter.getValue().getAsBoolean()) {
                    DiscoveredGraphQlEngine discoveredGraphQlEngine =
                            new DiscoveredGraphQlEngine(
                                    fingerprinter.getKey(),
                                    lastQueryMsg.getRequestHeader().getURI());
                    handleDetectedEngine(discoveredGraphQlEngine);
                    raiseFingerprintingAlert(discoveredGraphQlEngine);
                    break;
                }
            } catch (Exception e) {
                LOGGER.warn("Failed to fingerprint GraphQL engine: {}", fingerprinter.getKey(), e);
            }
        }
        queryCache.clear();
    }

    private static void handleDetectedEngine(DiscoveredGraphQlEngine discoveredGraphQlEngine) {
        for (DiscoveredGraphQlEngineHandler handler : handlers) {
            try {
                handler.process(discoveredGraphQlEngine);
            } catch (Exception ex) {
                LOGGER.error("Unable to handle: {}", discoveredGraphQlEngine.getName(), ex);
            }
        }
    }

    void sendQuery(String query) {
        lastQueryMsg =
                queryCache.computeIfAbsent(
                        query,
                        k -> requestor.sendQuery(k, GraphQlParam.RequestMethodOption.POST_JSON));
    }

    boolean errorContains(String substring) {
        return errorContains(substring, "message");
    }

    boolean errorContains(String substring, String errorField) {
        JsonNode errors = getResponseJsonField("errors");
        if (errors == null || !errors.isArray()) {
            return false;
        }
        for (var error : errors) {
            if (!error.isObject()) {
                continue;
            }
            var errorFieldValue = error.get(errorField);
            if (errorFieldValue == null) {
                continue;
            }
            if (errorFieldValue.asText().contains(substring)) {
                setMatchedEvidence(substring);
                return true;
            }
        }
        return false;
    }

    /**
     * Sets the matched evidence and captures the current message. This ensures that when an alert
     * is raised, the evidence is always from the associated message.
     *
     * @param evidence the matched string to use as evidence
     */
    private void setMatchedEvidence(String evidence) {
        matchedString = evidence;
        matchedMessage = lastQueryMsg;
    }

    /**
     * Parses the last query response body as JSON and returns the root node.
     *
     * @return the root JsonNode, or null if parsing fails or response is not JSON
     */
    private JsonNode getResponseJson() {
        if (lastQueryMsg == null || !lastQueryMsg.getResponseHeader().isJson()) {
            return null;
        }
        try {
            return OBJECT_MAPPER.readValue(
                    lastQueryMsg.getResponseBody().toString(), JsonNode.class);
        } catch (Exception ignored) {
            return null;
        }
    }

    /**
     * Parses the last query response body as JSON and returns a specific field.
     *
     * @param fieldName the name of the field to retrieve from the root JSON object
     * @return the JsonNode for the specified field, or null if parsing fails or field doesn't exist
     */
    private JsonNode getResponseJsonField(String fieldName) {
        JsonNode root = getResponseJson();
        return root != null ? root.get(fieldName) : null;
    }

    static Alert.Builder createFingerprintingAlert(
            DiscoveredGraphQlEngine discoveredGraphQlEngine) {
        return Alert.builder()
                .setPluginId(ExtensionGraphQl.TOOL_ALERT_ID)
                .setAlertRef(FINGERPRINTING_ALERT_REF)
                .setName(Constant.messages.getString("graphql.fingerprinting.alert.name"))
                .setDescription(
                        Constant.messages.getString(
                                "graphql.fingerprinting.alert.desc",
                                discoveredGraphQlEngine.getName(),
                                discoveredGraphQlEngine.getTechnologies()))
                .setReference(discoveredGraphQlEngine.getDocsUrl())
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setRisk(Alert.RISK_INFO)
                .setCweId(205)
                .setWascId(45)
                .setSource(Alert.Source.TOOL)
                .setTags(FINGERPRINTING_ALERT_TAGS);
    }

    void raiseFingerprintingAlert(DiscoveredGraphQlEngine discoveredGraphQlEngine) {
        var extAlert =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
        if (extAlert == null) {
            return;
        }

        // Use matchedMessage if available (it was captured when evidence was set),
        // otherwise fall back to lastQueryMsg for backward compatibility
        HttpMessage alertMessage = matchedMessage != null ? matchedMessage : lastQueryMsg;

        Alert alert =
                createFingerprintingAlert(discoveredGraphQlEngine)
                        .setEvidence(matchedString)
                        .setMessage(alertMessage)
                        .setUri(endpointUrl.toString())
                        .build();
        extAlert.alertFound(alert, null);
    }

    private boolean checkAbsintheEngine() {
        sendQuery("{zaproxy}");
        return errorContains("Cannot query field \"zaproxy\" on type \"RootQueryType\".");
    }

    private boolean checkAgooEngine() {
        sendQuery("{zaproxy}");
        return errorContains("eval error", "code");
    }

    private boolean checkApolloEngine() {
        int apolloScore = 0;

        // Test 1: Check for Apollo-specific directive error format
        sendQuery("query @skip {__typename}");
        if (errorContains(
                "Directive \"@skip\" argument \"if\" of type \"Boolean!\" is required, but it was not provided.")) {
            apolloScore++;
        }

        // Test 2: Apollo-specific directive location error
        sendQuery("query @deprecated {__typename}");
        if (errorContains("Directive \"@deprecated\" may not be used on QUERY.")) {
            apolloScore++;
        }

        // Test 3: Apollo Server often includes extensions in responses
        if (apolloScore >= 1) {
            sendQuery("query { __typename }");
            JsonNode extensions = getResponseJsonField("extensions");

            // Apollo Server often includes tracing or cache hints
            if (extensions != null && extensions.isObject()) {
                if (extensions.has("tracing")) {
                    setMatchedEvidence("tracing");
                    return true;
                }
                if (extensions.has("cacheControl")) {
                    setMatchedEvidence("cacheControl");
                    return true;
                }
            }
        }
        // Require at least 2 Apollo indicators to reduce false positives
        return apolloScore >= 2;
    }

    private boolean checkAriadneEngine() {
        sendQuery("{__typename @abc}");
        if (errorContains("Unknown directive '@abc'.")) {
            JsonNode data = getResponseJsonField("data");
            if (data == null) {
                setMatchedEvidence(null);
                return true;
            }
        }
        sendQuery("");
        return errorContains("The query must be a string.");
    }

    private boolean checkAwsAppSyncEngine() {
        // Send a query that will trigger an error response
        sendQuery("query @skip {__typename}");

        if (lastQueryMsg == null) {
            return false;
        }

        // Check for AWS-specific response header (very reliable indicator)
        String amznRequestId = lastQueryMsg.getResponseHeader().getHeader("x-amzn-requestid");
        if (amznRequestId != null && !amznRequestId.isEmpty()) {
            setMatchedEvidence("x-amzn-requestid");
            return true;
        }

        // Check for AppSync-specific errorType field in errors
        // AppSync uses "errorType" directly in error objects, which is non-standard
        // Vanilla graphql-java uses extensions.classification instead
        JsonNode errors = getResponseJsonField("errors");
        if (errors != null && errors.isArray() && !errors.isEmpty()) {
            JsonNode error = errors.get(0);
            if (error != null && error.has("errorType")) {
                String errorType = error.get("errorType").asText();
                if (errorType != null && !errorType.isEmpty()) {
                    setMatchedEvidence(errorType);
                    return true;
                }
            }
        }

        return false;
    }

    private boolean checkCalibanEngine() {
        sendQuery("{__typename} fragment zap on __Schema {directives {name}}");
        return errorContains("Fragment 'zap' is not used in any spread");
    }

    private boolean checkDgraphEngine() {
        sendQuery("{__typename @cascade}");
        JsonNode data = getResponseJsonField("data");
        if (data != null && data.isObject()) {
            if (data.has("__typename") && "Query".equals(data.get("__typename").asText())) {
                setMatchedEvidence("Query");
                return true;
            }
        }
        sendQuery("{__typename}");
        return errorContains(
                "Not resolving __typename. There's no GraphQL schema in Dgraph. Use the /admin API to add a GraphQL schema");
    }

    private boolean checkDianajlEngine() {
        sendQuery("queryy {__typename}");
        return errorContains("Syntax Error GraphQL request (1:1) Unexpected Name \"queryy\"");
    }

    private boolean checkDirectusEngine() {
        sendQuery("");
        JsonNode errors = getResponseJsonField("errors");
        if (errors == null || !errors.isArray() || errors.isEmpty()) {
            return false;
        }
        var error = errors.get(0);
        if (error == null || !error.isObject()) {
            return false;
        }
        JsonNode extensions = error.get("extensions");
        if (extensions == null || !extensions.isObject()) {
            return false;
        }
        if (extensions.has("code") && "INVALID_PAYLOAD".equals(extensions.get("code").asText())) {
            setMatchedEvidence("INVALID_PAYLOAD");
            return true;
        }
        return false;
    }

    private boolean checkFlutterEngine() {
        sendQuery("{__typename @deprecated}");
        return errorContains("Directive \"deprecated\" may not be used on FIELD.");
    }

    private boolean checkGqlGenEngine() {
        sendQuery("{__typename{}");
        if (errorContains("expected at least one definition")) {
            return true;
        }
        sendQuery("{alias^_:__typename {}");
        return errorContains("Expected Name, found <Invalid>");
    }

    private boolean checkGrapheneEngine() {
        sendQuery("aaa");
        return errorContains("Syntax Error GraphQL (1:1)");
    }

    private boolean checkGraphQlByPopEngine() {
        sendQuery("{alias1$1:__typename}");
        JsonNode data = getResponseJsonField("data");
        if (data != null && data.isObject()) {
            if (data.has("alias1$1") && "QueryRoot".equals(data.get("alias1$1").asText())) {
                setMatchedEvidence("QueryRoot");
                return true;
            }
        }
        sendQuery("query aa#aa {__typename}");
        if (errorContains("Unexpected token \"END\"")) {
            return true;
        }
        sendQuery("query @skip {__typename}");
        if (errorContains("Argument 'if' cannot be empty, so directive 'skip' has been ignored")) {
            return true;
        }
        sendQuery("query @doesnotexist {__typename}");
        if (errorContains("No DirectiveResolver resolves directive with name 'doesnotexist'")) {
            return true;
        }
        sendQuery("");
        return errorContains("The query in the body is empty");
    }

    private boolean checkGraphqlDotNetEngine() {
        sendQuery("query @skip {__typename}");
        return errorContains("Directive 'skip' may not be used on Query.");
    }

    private boolean checkGraphQlGoEngine() {
        sendQuery("{__typename{}");
        if (errorContains("Unexpected empty IN")) {
            return true;
        }
        sendQuery("");
        if (errorContains("Must provide an operation.")) {
            return true;
        }
        sendQuery("{__typename}");
        JsonNode data = getResponseJsonField("data");
        if (data != null && data.isObject()) {
            if (data.has("__typename") && "RootQuery".equals(data.get("__typename").asText())) {
                setMatchedEvidence("RootQuery");
                return true;
            }
        }
        return false;
    }

    private boolean checkGraphQlJavaEngine() {
        sendQuery("queryy {__typename}");
        if (errorContains("Invalid Syntax : offending token 'queryy'")) {
            return true;
        }
        sendQuery("query @aaa@aaa {__typename}");
        if (errorContains(
                "Validation error of type DuplicateDirectiveName: Directives must be uniquely named within a location.")) {
            return true;
        }
        sendQuery("");
        return errorContains("Invalid Syntax : offending token '<EOF>'");
    }

    private boolean checkGraphQlPhpEngine() {
        sendQuery("query @deprecated {__typename}");
        return errorContains("Directive \"deprecated\" may not be used on \"QUERY\".");
    }

    private boolean checkGraphQlRubyEngine() {
        sendQuery("query @skip {__typename}");
        if (errorContains(
                        "'@skip' can't be applied to queries (allowed: fields, fragment spreads, inline fragments)")
                || errorContains("Directive 'skip' is missing required arguments: if")) {
            return true;
        }
        sendQuery("query @deprecated {__typename}");
        if (errorContains("'@deprecated' can't be applied to queries")) {
            return true;
        }
        sendQuery("{__typename{}");
        if (errorContains("Parse error on \"}\" (RCURLY)")) {
            return true;
        }
        sendQuery("{__typename @skip}");
        return errorContains("Directive 'skip' is missing required arguments: if");
    }

    private boolean checkGraphQlYogaEngine() {
        // Yoga-specific subscription error (v2+)
        sendQuery("subscription {__typename}");
        return errorContains("asyncExecutionResult[Symbol.asyncIterator] is not a function");
    }

    private boolean checkHasuraEngine() {
        sendQuery("query @cached {__typename}");
        JsonNode data = getResponseJsonField("data");
        if (data != null && data.isObject()) {
            if (data.has("__typename") && "query_root".equals(data.get("__typename").asText())) {
                setMatchedEvidence("query_root");
                return true;
            }
        }
        sendQuery("{zaproxy}");
        if (errorContains("field \"zaproxy\" not found in type: 'query_root'")) {
            return true;
        }
        sendQuery("query @skip {__typename}");
        if (errorContains("directive \"skip\" is not allowed on a query")) {
            return true;
        }
        sendQuery("{__schema}");
        return errorContains("missing selection set for \"__Schema\"");
    }

    private boolean checkHotchocolateEngine() {
        sendQuery("queryy  {__typename}");
        if (errorContains("Unexpected token: Name.")) {
            return true;
        }
        sendQuery("query @aaa@aaa {__typename}");
        return errorContains(
                "The specified directive `aaa` is not supported by the current schema.");
    }

    private boolean checkHyperGraphQlEngine() {
        sendQuery("queryy {__typename}");
        if (errorContains("Validation error of type InvalidSyntax: Invalid query syntax.")) {
            return true;
        }
        sendQuery("query {alias1:__typename @deprecated}");
        return errorContains(
                "Validation error of type UnknownDirective: Unknown directive deprecated @ '__typename'");
    }

    private boolean checkInigoEngine() {
        // https://github.com/dolevf/graphw00f/commit/52e25d376f5fd4dcad062ba79a1b6c3e5e1c68dc
        sendQuery("query {__typename}");
        JsonNode exts = getResponseJsonField("extensions");
        if (exts != null && exts.isObject() && exts.has("inigo")) {
            setMatchedEvidence("inigo");
            return true;
        }
        return false;
    }

    private boolean checkJaalEngine() {
        sendQuery("");
        return errorContains("must have a single query");
    }

    private boolean checkJuniperEngine() {
        sendQuery("queryy {__typename}");
        if (errorContains("Unexpected \"queryy\"")) {
            return true;
        }
        sendQuery("");
        return errorContains("Unexpected end of input");
    }

    private boolean checkLaciniaEngine() {
        sendQuery("{zaproxy}");
        return errorContains("Cannot query field `zaproxy' on type `QueryRoot'.");
    }

    private boolean checkLighthouseEngine() {
        // Test 1: Lighthouse's specific bug with boolean variable validation
        sendQuery("{__typename @include(if: falsee)}");

        boolean hasInternalError = errorContains("Internal server error");

        if (!hasInternalError) {
            return false;
        }

        // Test 2: Lighthouse (Laravel) includes category in extensions
        // Check for errors[].extensions.category = "internal"
        boolean hasInternalCategory = false;
        JsonNode errors = getResponseJsonField("errors");

        if (errors != null && errors.isArray() && !errors.isEmpty()) {
            JsonNode firstError = errors.get(0);
            JsonNode extensions = firstError.get("extensions");

            if (extensions != null && extensions.isObject()) {
                // Lighthouse includes 'category' field in extensions
                if (extensions.has("category")
                        && "internal".equals(extensions.get("category").asText())) {
                    hasInternalCategory = true;

                    // Additional Lighthouse indicators add more confidence
                    // Use actual content from response as evidence
                    if (extensions.has("trace")) {
                        setMatchedEvidence("trace");
                        return true;
                    }
                    if (extensions.has("file")) {
                        setMatchedEvidence("file");
                        return true;
                    }
                    // Has category internal in extensions, which is fairly specific
                    setMatchedEvidence("internal");
                    return true;
                }
            }
        }

        // If we have internal error but no category, do additional checks
        if (hasInternalError && !hasInternalCategory) {
            // Test 3: Lighthouse-specific directive handling
            sendQuery("query @guard(with: \"api\") { __typename }");
            if (errorContains("Directive \"@guard\" may not be used on QUERY")
                    || errorContains("Unknown directive")) {
                // Verify it's Lighthouse by checking error structure
                JsonNode guardErrors = getResponseJsonField("errors");
                if (guardErrors != null && guardErrors.isArray() && !guardErrors.isEmpty()) {
                    // Lighthouse errors have specific structure
                    JsonNode error = guardErrors.get(0);
                    if (error.has("extensions") && error.has("message") && error.has("locations")) {
                        // Use the actual error message as evidence
                        setMatchedEvidence(error.get("message").asText());
                        return true;
                    }
                }
            }

            // Test 4: Lighthouse-specific validation error format
            sendQuery("query { __typename __typename }");
            if (errorContains(
                    "Fields \"__typename\" conflict because they have differing arguments")) {
                // errorContains already sets the evidence
                return true;
            }
        }

        // Only accept if we found the category field in extensions
        return hasInternalCategory;
    }

    private boolean checkMercuriusEngine() {
        sendQuery("");
        return errorContains("Unknown query");
    }

    private boolean checkMorpheusEngine() {
        sendQuery("queryy {__typename}");
        return errorContains("expecting white space") || errorContains("offset");
    }

    private boolean checkPgGraphqlEngine() {
        sendQuery("query { __typename @skip(aa:tr");
        // https://github.com/supabase/pg_graphql/blob/5f9c62b85293b753676b07c9b309670a77e6310e/src/parser_util.rs#L65
        return (errorContains("Unknown argument to @skip: aa"));
    }

    private boolean checkSangriaEngine() {
        sendQuery("queryy {__typename}");
        JsonNode syntaxError = getResponseJsonField("syntaxError");
        if (syntaxError == null || !syntaxError.isValueNode()) {
            return false;
        }
        String expectedError =
                "Syntax error while parsing GraphQL query. Invalid input \"queryy\", expected ExecutableDefinition or TypeSystemDefinition";
        if (syntaxError.asText().contains(expectedError)) {
            setMatchedEvidence(expectedError);
            return true;
        }
        return false;
    }

    private boolean checkStrawberryEngine() {
        sendQuery("query @deprecated {__typename}");
        if (!errorContains("Directive '@deprecated' may not be used on query.")) {
            return false;
        }

        // Strawberry returns both error and data field
        JsonNode root = getResponseJson();
        if (root == null) {
            return false;
        }

        // Must have both errors and data (Strawberry-specific behavior)
        if (!root.has("data")) {
            return false;
        }

        // Verify we have errors array
        JsonNode errors = root.get("errors");
        if (errors != null && errors.isArray() && !errors.isEmpty()) {
            setMatchedEvidence("Directive '@deprecated' may not be used on query.");
            return true;
        }
        return false;
    }

    private boolean checkTailcallEngine() {
        sendQuery("aa {__typename}");
        return errorContains("expected executable_definition");
    }

    private boolean checkTartifletteEngine() {
        // Check 1: The known typo (for older versions)
        sendQuery("query @doesnotexist {__typename}");
        // https://github.com/tartiflette/tartiflette/blob/421c1e937f553d6a5bf2f30154022c0d77053cfb/tartiflette/language/validators/query/directives_are_defined.py#L22
        if (errorContains("Unknow Directive < @doesnotexist >.")) {
            return true;
        }
        // Check 2: Fallback for if they fix the typo
        if (errorContains("Unknown Directive < @doesnotexist >.")) {
            return true;
        }

        // Check 3: Tartiflette-specific error format with angle brackets
        sendQuery("query @skip {__typename}");
        if (errorContains("Missing mandatory argument < if > in directive < @skip >.")) {
            return true;
        }

        // Check 4: Tartiflette's unique field error format
        sendQuery("{zaproxy}");
        if (errorContains("Field zaproxy doesn't exist on Query")) {
            return true;
        }

        // Check 5: Tartiflette's specific syntax error format
        sendQuery("queryy {__typename}");
        if (errorContains("syntax error, unexpected IDENTIFIER")) {
            // Accept the syntax error as it's fairly specific to Tartiflette
            // The specific format "syntax error, unexpected IDENTIFIER" is characteristic
            return true;
        }

        // Check 6: Unique location error format
        sendQuery("{__typename @deprecated}");
        return errorContains("Directive < @deprecated > is not used in a valid location.");
    }

    private boolean checkWpGraphQlEngine() {
        sendQuery("");
        if (errorContains(
                "GraphQL Request must include at least one of those two parameters: \"query\" or \"queryId\"")) {
            return true;
        }
        sendQuery("{alias1$1:__typename}");
        if (!errorContains("Syntax Error: Expected Name, found $")) {
            return false;
        }
        JsonNode extensions = getResponseJsonField("extensions");
        if (extensions != null && extensions.isObject()) {
            JsonNode debug = extensions.get("debug");
            if (debug != null && debug.isArray() && !debug.isEmpty()) {
                var debugObject = debug.get(0);
                String expectedDebugType = "DEBUG_LOGS_INACTIVE";
                if (debugObject.has("type")
                        && expectedDebugType.equals(debugObject.get("type").asText())) {
                    setMatchedEvidence(expectedDebugType);
                    return true;
                }
                String expectedDebugMessage =
                        "GraphQL Debug logging is not active. To see debug logs, GRAPHQL_DEBUG must be enabled.";
                if (debugObject.has("message")
                        && expectedDebugMessage.equals(debugObject.get("message").asText())) {
                    setMatchedEvidence(expectedDebugMessage);
                    return true;
                }
            }
        }
        return false;
    }

    public static void addEngineHandler(DiscoveredGraphQlEngineHandler handler) {
        if (handlers == null) {
            resetHandlers();
        }
        handlers.add(handler);
    }

    public static void resetHandlers() {
        handlers = new ArrayList<>(2);
    }

    public static class DiscoveredGraphQlEngine {
        private static final String PREFIX = "graphql.engine.";
        private String enginePrefix;
        private String name;
        private String docsUrl;
        private String technologies;
        private URI uri;

        public DiscoveredGraphQlEngine(String engineId, URI uri) {
            this.enginePrefix = PREFIX + engineId + ".";

            this.name = Constant.messages.getString(enginePrefix + "name");
            this.docsUrl = Constant.messages.getString(enginePrefix + "docsUrl");
            this.technologies = Constant.messages.getString(enginePrefix + "technologies");
            this.uri = uri;
        }

        public String getName() {
            return name;
        }

        public String getDocsUrl() {
            return docsUrl;
        }

        public String getTechnologies() {
            return technologies;
        }

        public URI getUri() {
            return uri;
        }
    }
}
