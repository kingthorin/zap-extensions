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
package org.zaproxy.zap.extension.scripts.automation.actions;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Locale;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobParameters;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link RunScriptAction}. */
class RunScriptActionUnitTest extends TestUtils {

    private static final String JOB_NAME = "TestJob";
    private static final String ZEST_ENGINE_NAME = "Mozilla Zest";

    private ExtensionScript extScript;
    private ExtensionLoader extensionLoader;
    private AutomationProgress progress;
    private AutomationEnvironment env;
    private ScriptJobParameters parameters;
    private RunScriptAction action;

    @BeforeAll
    static void setUpAll() {
        Constant.messages = new I18N(Locale.ROOT);
    }

    /** Stub for chain tests (no Zest): returns first script from chain. */
    private static final ExtensionAdaptor ZEST_RUNNABLE_STUB =
            new ExtensionAdaptor("ExtensionZest") {
                @SuppressWarnings("unused")
                public ScriptWrapper getRunnableForChain(
                        List<ScriptWrapper> scripts, String runName) {
                    return scripts.isEmpty() ? null : scripts.get(0);
                }
            };

    @BeforeEach
    void setUp() {
        extScript = mock(ExtensionScript.class);
        extensionLoader = mock(ExtensionLoader.class);
        given(extensionLoader.getExtension(ExtensionScript.class)).willReturn(extScript);
        lenient()
                .when(extensionLoader.getExtension("ExtensionZest"))
                .thenReturn(ZEST_RUNNABLE_STUB);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);

        progress = new AutomationProgress();
        env = new AutomationEnvironment(progress);
        parameters =
                new ScriptJobParameters(
                        RunScriptAction.NAME,
                        ExtensionScript.TYPE_STANDALONE,
                        null,
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        null);
        action = new RunScriptAction(parameters);
    }

    /** Zest standalone wrapper with getZestScript for chain validation. */
    private ScriptWrapper createMockZestWrapper(String name) {
        TestZestScriptWrapper wrapper = new TestZestScriptWrapper();
        wrapper.setName(name);
        wrapper.setEngineName(ZEST_ENGINE_NAME);
        wrapper.setType(new ScriptType(ExtensionScript.TYPE_STANDALONE, null, null, false));
        return wrapper;
    }

    /** Wrapper without getZestScript (fails chain validation). */
    private ScriptWrapper createMockNonZestWrapper(
            String name, String engineName, String typeName) {
        ScriptWrapper wrapper = mock(ScriptWrapper.class);
        given(wrapper.getName()).willReturn(name);
        given(wrapper.getEngineName()).willReturn(engineName);
        given(wrapper.getTypeName()).willReturn(typeName);
        return wrapper;
    }

    /** ScriptWrapper with getZestScript for chain/Zest merge. */
    public static class TestZestScriptWrapper extends ScriptWrapper {
        public Object getZestScript() {
            return new Object();
        }
    }

    /** Chain Validation Tests */
    @Test
    void shouldValidateChainWithValidZestStandaloneScripts() {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        ScriptWrapper script2 = createMockZestWrapper("script2");
        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("script2")).willReturn(script2);

        parameters.setChain(List.of("script1", "script2"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldRejectChainWithNonExistentScript() {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("nonExistent")).willReturn(null);

        parameters.setChain(List.of("script1", "nonExistent"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(), contains("!scripts.automation.error.chainScriptNotFound!"));
    }

    @Test
    void shouldRejectChainWithNonStandaloneScript() {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        ScriptWrapper script2 = mock(ScriptWrapper.class);
        lenient().when(script2.getName()).thenReturn("script2");
        lenient().when(script2.getEngineName()).thenReturn(ZEST_ENGINE_NAME);
        lenient().when(script2.getTypeName()).thenReturn("targeted");

        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("script2")).willReturn(script2);

        parameters.setChain(List.of("script1", "script2"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(),
                contains("!scripts.automation.error.chainScriptNotZestStandalone!"));
    }

    @Test
    void shouldRejectChainWithNonZestScript() {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        ScriptWrapper script2 = mock(ScriptWrapper.class);
        lenient().when(script2.getName()).thenReturn("script2");
        lenient().when(script2.getEngineName()).thenReturn("JavaScript");
        lenient().when(script2.getTypeName()).thenReturn(ExtensionScript.TYPE_STANDALONE);

        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("script2")).willReturn(script2);

        parameters.setChain(List.of("script1", "script2"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(),
                contains("!scripts.automation.error.chainScriptNotZestScript!"));
    }

    @Test
    void shouldRejectChainWithScriptMissingRequiredMethods() {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        ScriptWrapper script2 =
                createMockNonZestWrapper(
                        "script2", ZEST_ENGINE_NAME, ExtensionScript.TYPE_STANDALONE);
        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("script2")).willReturn(script2);

        parameters.setChain(List.of("script1", "script2"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(),
                contains("!scripts.automation.error.chainScriptMissingMethods!"));
    }

    @Test
    void shouldHandleEmptyChain() {
        // Given
        parameters.setChain(List.of());

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then — empty chain → no name, findScript fails
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.scriptNameNotFound!"));
    }

    /** Chain Execution Tests */
    @Test
    void shouldExecuteChainWithTwoScripts() throws Exception {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        ScriptWrapper script2 = createMockZestWrapper("script2");
        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("script2")).willReturn(script2);

        parameters.setChain(List.of("script1", "script2"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        verify(extScript, times(1)).invokeScript(script1);
    }

    @Test
    void shouldExecuteChainWithThreeScripts() throws Exception {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        ScriptWrapper script2 = createMockZestWrapper("script2");
        ScriptWrapper script3 = createMockZestWrapper("script3");
        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("script2")).willReturn(script2);
        given(extScript.getScript("script3")).willReturn(script3);

        parameters.setChain(List.of("script1", "script2", "script3"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        verify(extScript, times(1)).invokeScript(script1);
    }

    @Test
    void shouldStopChainOnFirstScriptFailure() throws Exception {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        ScriptWrapper script2 = createMockZestWrapper("script2");
        ScriptWrapper script3 = createMockZestWrapper("script3");
        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("script2")).willReturn(script2);
        given(extScript.getScript("script3")).willReturn(script3);
        when(extScript.invokeScript(script1)).thenThrow(new RuntimeException("Script failed"));

        parameters.setChain(List.of("script1", "script2", "script3"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(), contains("!scripts.automation.error.chainExecutionFailed!"));
        verify(extScript, times(1)).invokeScript(script1);
    }

    @Test
    void shouldNotExecuteChainForSingleScript() throws Exception {
        // Given
        ScriptWrapper script1 = createMockZestWrapper("script1");
        given(extScript.getScript("script1")).willReturn(script1);

        parameters.setName("script1");
        parameters.setChain(List.of("script1"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        verify(extScript, times(1)).invokeScript(script1);
    }

    @Test
    void shouldExecuteTargetedScriptWhenTypeTargetedAndTargetFound() throws Exception {
        // Given
        parameters.setType(ExtensionScript.TYPE_TARGETED);
        parameters.setName("myScript");
        parameters.setTarget("http://example.com/");
        ScriptWrapper script = createMockZestWrapper("myScript");
        given(extScript.getScript("myScript")).willReturn(script);

        HttpMessage httpMessage = new HttpMessage();
        HistoryReference historyRef = mock(HistoryReference.class);
        given(historyRef.getHttpMessage()).willReturn(httpMessage);
        SiteNode siteNode = mock(SiteNode.class);
        given(siteNode.getHistoryReference()).willReturn(historyRef);
        SiteMap siteMap = mock(SiteMap.class);
        given(siteMap.findNode(any(URI.class))).willReturn(siteNode);
        Session session = mock(Session.class);
        given(session.getSiteTree()).willReturn(siteMap);
        Model model = mock(Model.class);
        given(model.getSession()).willReturn(session);
        Control.initSingletonForTesting(model, extensionLoader);
        Model.setSingletonForTesting(model);

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        verify(extScript, times(1)).invokeTargetedScript(script, httpMessage);
    }

    /** Single Script Execution Tests */
    @Test
    void shouldExecuteSingleStandaloneScript() throws Exception {
        // Given
        ScriptWrapper script = createMockZestWrapper("myScript");
        given(extScript.getScript("myScript")).willReturn(script);

        parameters.setName("myScript");

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        verify(extScript, times(1)).invokeScript(script);
    }

    @Test
    void shouldReportErrorIfSingleScriptNotFound() {
        // Given
        given(extScript.getScript("nonExistent")).willReturn(null);

        parameters.setName("nonExistent");

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(progress.getErrors(), contains("!scripts.automation.error.scriptNameNotFound!"));
    }

    @Test
    void shouldHandleReflectionFailureGracefully() {
        // Given
        ScriptWrapper script1 = mock(ScriptWrapper.class);
        lenient().when(script1.getName()).thenReturn("script1");
        lenient().when(script1.getEngineName()).thenReturn(ZEST_ENGINE_NAME);
        lenient().when(script1.getTypeName()).thenReturn(ExtensionScript.TYPE_STANDALONE);

        given(extScript.getScript("script1")).willReturn(script1);

        parameters.setChain(List.of("script1", "script2"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(),
                contains("!scripts.automation.error.chainScriptMissingMethods!"));
    }

    @Test
    void shouldReportChainReflectionFailedWhenZestNotLoaded() {
        // Given
        given(extensionLoader.getExtension("ExtensionZest")).willReturn(null);
        ScriptWrapper script1 = createMockZestWrapper("script1");
        ScriptWrapper script2 = createMockZestWrapper("script2");
        given(extScript.getScript("script1")).willReturn(script1);
        given(extScript.getScript("script2")).willReturn(script2);
        parameters.setChain(List.of("script1", "script2"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(), contains("!scripts.automation.error.chainReflectionFailed!"));
    }

    @Test
    void shouldRejectChainAtRuntimeWhenTypeNotStandalone() throws Exception {
        // Given: type targeted + chain set → runScriptChain rejects early
        parameters.setType(ExtensionScript.TYPE_TARGETED);
        parameters.setChain(List.of("script1", "script2"));
        lenient().when(extScript.getScript("script1")).thenReturn(createMockZestWrapper("script1"));
        lenient().when(extScript.getScript("script2")).thenReturn(createMockZestWrapper("script2"));

        // When
        action.runJob(JOB_NAME, env, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors(),
                contains("!scripts.automation.error.chainRequiresStandalone!"));
        verify(extScript, times(0)).invokeScript(any());
    }

    /** Parameter Validation Tests */
    @Test
    void shouldWarnWhenBothNameAndChainSpecified() {
        // Given
        parameters.setName("myScript");
        parameters.setChain(List.of("script1", "script2"));

        // When
        action.verifyParameters(JOB_NAME, parameters, progress);

        // Then
        assertThat(progress.getWarnings(), hasSize(1));
        assertThat(
                progress.getWarnings(),
                contains("!scripts.automation.warn.chainAndNameBothSpecified!"));
    }

    @Test
    void shouldRejectChainWithTargetedScriptType() {
        // Given
        ScriptJobParameters targetedParams =
                new ScriptJobParameters(
                        RunScriptAction.NAME,
                        ExtensionScript.TYPE_TARGETED,
                        ZEST_ENGINE_NAME,
                        "",
                        "",
                        "http://example.com/",
                        "",
                        "",
                        "",
                        null);
        targetedParams.setChain(List.of("script1", "script2"));
        given(extScript.getEngineWrapper(ZEST_ENGINE_NAME))
                .willReturn(mock(ScriptEngineWrapper.class));
        RunScriptAction targetedAction = new RunScriptAction(targetedParams);

        // When
        List<String> issues = targetedAction.verifyParameters(JOB_NAME, targetedParams, progress);

        // Then
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                issues,
                hasItem(containsString("scripts.automation.error.chainRequiresStandalone")));
    }
}
