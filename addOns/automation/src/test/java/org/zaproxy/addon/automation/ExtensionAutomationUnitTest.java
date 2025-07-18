/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.TableContext;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.jobs.ActiveScanConfigJob;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.jobs.ActiveScanPolicyJob;
import org.zaproxy.addon.automation.jobs.DelayJob;
import org.zaproxy.addon.automation.jobs.ExitStatusJob;
import org.zaproxy.addon.automation.jobs.ParamsJob;
import org.zaproxy.addon.automation.jobs.RequestorJob;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link ExtensionAutomation}. */
class ExtensionAutomationUnitTest extends TestUtils {

    private static MockedStatic<CommandLine> mockedCmdLine;

    @BeforeAll
    static void init() throws Exception {
        mockedCmdLine = Mockito.mockStatic(CommandLine.class);
    }

    @AfterAll
    static void close() throws ReflectiveOperationException {
        mockedCmdLine.close();
    }

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        Database database = mock(Database.class);
        lenient().when(model.getDb()).thenReturn(database);
        TableContext tableContext = mock(TableContext.class);
        lenient().when(database.getTableContext()).thenReturn(tableContext);

        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
    }

    @Test
    void shouldReturnDefaultData() {
        // Given / When
        ExtensionAutomation extAuto = new ExtensionAutomation();

        // Then
        assertThat(extAuto.canUnload(), is(equalTo(true)));
        assertThat(extAuto.getI18nPrefix(), is(equalTo("automation")));
        assertThat(extAuto.getAuthor(), is(equalTo("ZAP Dev Team")));
    }

    @SuppressWarnings("deprecation")
    @Test
    void shouldRegisterBuiltInJobsOnInit() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();

        // When
        extAuto.init();
        Map<String, AutomationJob> jobs = extAuto.getAutomationJobs();

        // Then
        assertThat(jobs.size(), is(equalTo(8)));
        assertThat(
                jobs.containsKey(org.zaproxy.addon.automation.jobs.AddOnJob.JOB_NAME),
                is(equalTo(true)));
        assertThat(jobs.containsKey(DelayJob.JOB_NAME), is(equalTo(true)));
        assertThat(jobs.containsKey(ActiveScanJob.JOB_NAME), is(equalTo(true)));
        assertThat(jobs.containsKey(ActiveScanConfigJob.JOB_NAME), is(equalTo(true)));
        assertThat(jobs.containsKey(ActiveScanPolicyJob.JOB_NAME), is(equalTo(true)));
        assertThat(jobs.containsKey(ParamsJob.JOB_NAME), is(equalTo(true)));
        assertThat(jobs.containsKey(RequestorJob.JOB_NAME), is(equalTo(true)));
        assertThat(jobs.containsKey(ExitStatusJob.JOB_NAME), is(equalTo(true)));
    }

    @Test
    void shouldRegisterNewJob() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        AutomationJob job = new AutomationJobImpl("testjob");

        // When
        extAuto.registerAutomationJob(job);
        Map<String, AutomationJob> jobs = extAuto.getAutomationJobs();

        // Then
        assertThat(jobs.size(), is(equalTo(1)));
        assertThat(jobs.containsKey(job.getType()), is(equalTo(true)));
    }

    @Test
    void shouldUnregisterExistingJob() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        AutomationJob job = new AutomationJobImpl("testjob");
        extAuto.registerAutomationJob(job);

        // When
        extAuto.unregisterAutomationJob(job);

        // Then
        Map<String, AutomationJob> jobs = extAuto.getAutomationJobs();
        assertThat(jobs.size(), is(equalTo(0)));
        assertThat(jobs.containsKey(job.getType()), is(equalTo(false)));
    }

    @Test
    void shouldCreateMinTemplateFile() throws Exception {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        extAuto.init();
        Path filePath = getResourcePath("resources/template-min.yaml");
        String expectedTemplate = new String(Files.readAllBytes(filePath));

        // When
        File f = File.createTempFile("ZAP-min-template-test", ".yaml");
        extAuto.generateTemplateFile(f.getAbsolutePath(), false);
        String generatedTemplate = new String(Files.readAllBytes(f.toPath()));

        // Then
        // If this fails then the easiest option is to generate the file using the cmdline option,
        // manually check it and then replace it in the resources directory
        assertThat(generatedTemplate.length(), is(equalTo(expectedTemplate.length())));
        assertThat(generatedTemplate, is(equalTo(expectedTemplate)));
    }

    @Test
    void shouldCreateMaxTemplateFile() throws Exception {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        extAuto.init();
        Path filePath = getResourcePath("resources/template-max.yaml");
        String expectedTemplate = new String(Files.readAllBytes(filePath));

        // When
        File f = File.createTempFile("ZAP-max-template-test", ".yaml");
        extAuto.generateTemplateFile(f.getAbsolutePath(), true);
        String generatedTemplate = new String(Files.readAllBytes(f.toPath()));

        // Then
        // If this fails then the easiest option is to generate the file using the cmdline option,
        // manually check it and then replace it in the resources directory
        assertThat(generatedTemplate.length(), is(equalTo(expectedTemplate.length())));
        assertThat(generatedTemplate, is(equalTo(expectedTemplate)));
    }

    @Test
    void shouldCreateConfigTemplateFile() throws Exception {
        // Given
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        ExtensionAutomation extAuto = new ExtensionAutomation();
        extAuto.init();
        Path filePath = getResourcePath("resources/template-config.yaml");
        String expectedTemplate = new String(Files.readAllBytes(filePath));

        // When
        File f = File.createTempFile("ZAP-config-template-test", ".yaml");
        extAuto.generateConfigFile(f.getAbsolutePath());
        String generatedTemplate = new String(Files.readAllBytes(f.toPath()));

        // Then
        assertThat(generatedTemplate.length(), is(equalTo(expectedTemplate.length())));
        assertThat(generatedTemplate, is(equalTo(expectedTemplate)));
    }

    @Test
    void shouldRunPlan() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        String job1Name = "job1";
        String job2Name = "job2";
        String job3Name = "job3";

        AutomationJobImpl job1 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job1Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        AutomationJobImpl job2 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job2Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        AutomationJobImpl job3 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job3Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        Path filePath = getResourcePath("resources/testplan-failonerror.yaml");
        InMemoryStats stats = new InMemoryStats();
        Stats.addListener(stats);

        // When
        extAuto.registerAutomationJob(job1);
        extAuto.registerAutomationJob(job2);
        extAuto.registerAutomationJob(job3);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());
        List<AutomationJob> runJobs = progress.getRunJobs();

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(runJobs.size(), is(equalTo(3)));
        assertThat(runJobs.get(0).getName(), is(equalTo("job1")));
        assertThat(((AutomationJobImpl) runJobs.get(0)).wasRun(), is(equalTo(true)));
        assertThat(runJobs.get(1).getName(), is(equalTo("job2")));
        assertThat(((AutomationJobImpl) runJobs.get(1)).wasRun(), is(equalTo(true)));
        assertThat(runJobs.get(2).getName(), is(equalTo("job3")));
        assertThat(((AutomationJobImpl) runJobs.get(2)).wasRun(), is(equalTo(true)));

        assertThat(stats.getStat(ExtensionAutomation.WARNING_COUNT_STATS), is(equalTo(0L)));
        assertThat(stats.getStat(ExtensionAutomation.ERROR_COUNT_STATS), is(equalTo(0L)));
        assertThat(stats.getStat(ExtensionAutomation.PLANS_RUN_STATS), is(equalTo(1L)));
        assertThat(stats.getStat(ExtensionAutomation.TOTAL_JOBS_RUN_STATS), is(equalTo(3L)));
        assertThat(
                stats.getStat(
                        ExtensionAutomation.JOBS_RUN_STATS_PREFIX
                                + "job1"
                                + ExtensionAutomation.JOBS_RUN_STATS_POSTFIX),
                is(equalTo(1L)));
        assertThat(
                stats.getStat(
                        ExtensionAutomation.JOBS_RUN_STATS_PREFIX
                                + "job2"
                                + ExtensionAutomation.JOBS_RUN_STATS_POSTFIX),
                is(equalTo(1L)));
        assertThat(
                stats.getStat(
                        ExtensionAutomation.JOBS_RUN_STATS_PREFIX
                                + "job3"
                                + ExtensionAutomation.JOBS_RUN_STATS_POSTFIX),
                is(equalTo(1L)));
    }

    @Test
    void shouldRunWithResolvedParams() throws ReflectiveOperationException {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        TestParamContainer tpc = new TestParamContainer();
        AutomationJobImpl job =
                new AutomationJobImpl(tpc) {
                    @Override
                    public String getType() {
                        return "job";
                    }

                    @Override
                    public Order getOrder() {
                        return Order.EXPLORE;
                    }
                };
        Path filePath = getResourcePath("resources/testplan-applyResolvedParams.yaml");

        // When
        extAuto.registerAutomationJob(job);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());
        List<AutomationJob> runJobs = progress.getRunJobs();

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(runJobs.size(), is(equalTo(1)));
        assertThat(runJobs.get(0).getName(), is(equalTo("job")));
        assertThat(((AutomationJobImpl) runJobs.get(0)).wasRun(), is(equalTo(true)));
        assertThat(tpc.getTestParam().getStringParam(), is(equalTo("true")));
    }

    @Nested
    class PlanInOrderTests {

        private AutomationJobImpl job1;
        private AutomationJobImpl job2;
        private AutomationJobImpl job3;
        private ExtensionAutomation extAuto;

        @BeforeEach
        void setup() {
            extAuto = new ExtensionAutomation();
            job1 =
                    new AutomationJobImpl() {
                        @Override
                        public String getType() {
                            return "job1";
                        }
                    };
            job2 =
                    new AutomationJobImpl() {
                        @Override
                        public String getType() {
                            return "job2";
                        }
                    };
            job3 =
                    new AutomationJobImpl() {
                        @Override
                        public String getType() {
                            return "job3";
                        }
                    };
        }

        @Test
        void shouldRunPlanInDefinedOrderWithSameRegOrder() {
            // Given
            Path filePath = getResourcePath("resources/testplan-failonerror.yaml");

            // When
            extAuto.registerAutomationJob(job1);
            extAuto.registerAutomationJob(job2);
            extAuto.registerAutomationJob(job3);
            AutomationProgress progress =
                    extAuto.runAutomationFile(filePath.toAbsolutePath().toString());
            List<AutomationJob> runJobs = progress.getRunJobs();

            // Then
            assertThat(runJobs.size(), is(equalTo(3)));
            assertThat(runJobs.get(0).getName(), is(equalTo("job1")));
            assertThat(((AutomationJobImpl) runJobs.get(0)).wasRun(), is(equalTo(true)));
            assertThat(runJobs.get(1).getName(), is(equalTo("job2")));
            assertThat(((AutomationJobImpl) runJobs.get(1)).wasRun(), is(equalTo(true)));
            assertThat(runJobs.get(2).getName(), is(equalTo("job3")));
            assertThat(((AutomationJobImpl) runJobs.get(2)).wasRun(), is(equalTo(true)));
        }

        @Test
        void shouldRunPlanInDefinedOrderWithDifferentRegOrder() {
            // Given
            Path filePath = getResourcePath("resources/testplan-failonerror.yaml");

            // When
            extAuto.registerAutomationJob(job3);
            extAuto.registerAutomationJob(job1);
            extAuto.registerAutomationJob(job2);
            AutomationProgress progress =
                    extAuto.runAutomationFile(filePath.toAbsolutePath().toString());
            List<AutomationJob> runJobs = progress.getRunJobs();

            // Then
            assertThat(runJobs.size(), is(equalTo(3)));
            assertThat(runJobs.get(0).getName(), is(equalTo("job1")));
            assertThat(((AutomationJobImpl) runJobs.get(0)).wasRun(), is(equalTo(true)));
            assertThat(runJobs.get(1).getName(), is(equalTo("job2")));
            assertThat(((AutomationJobImpl) runJobs.get(1)).wasRun(), is(equalTo(true)));
            assertThat(runJobs.get(2).getName(), is(equalTo("job3")));
            assertThat(((AutomationJobImpl) runJobs.get(2)).wasRun(), is(equalTo(true)));
        }
    }

    @Test
    void shouldFailPlanOnError() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        String job1Name = "job1";
        String job3Name = "job3";

        AutomationJobImpl job1 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job1Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        AutomationJobImpl job3 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job3Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        Path filePath = getResourcePath("resources/testplan-failonerror.yaml");
        InMemoryStats stats = new InMemoryStats();
        Stats.addListener(stats);

        // When
        extAuto.registerAutomationJob(job1);
        extAuto.registerAutomationJob(job3);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(job1.wasRun(), is(equalTo(false)));
        assertThat(job3.wasRun(), is(equalTo(false)));

        assertThat(stats.getStat(ExtensionAutomation.WARNING_COUNT_STATS), is(equalTo(0L)));
        assertThat(stats.getStat(ExtensionAutomation.ERROR_COUNT_STATS), is(equalTo(1L)));
        assertThat(stats.getStat(ExtensionAutomation.PLANS_RUN_STATS), is(equalTo(1L)));
        assertThat(stats.getStat(ExtensionAutomation.TOTAL_JOBS_RUN_STATS), is(nullValue()));
    }

    @Test
    void shouldContinuePlanOnError() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        String job1Name = "job1";
        String job2Name = "job2";
        String job3Name = "job3";

        AutomationJobImpl job1 =
                new AutomationJobImpl(true) {
                    @Override
                    public String getType() {
                        return job1Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }

                    @Override
                    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
                        super.runJob(env, progress);
                        progress.error("Test Error");
                    }
                };
        AutomationJobImpl job2 =
                new AutomationJobImpl(true) {
                    @Override
                    public String getType() {
                        return job2Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        AutomationJobImpl job3 =
                new AutomationJobImpl(true) {
                    @Override
                    public String getType() {
                        return job3Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        Path filePath = getResourcePath("resources/testplan-continueonerror.yaml");
        InMemoryStats stats = new InMemoryStats();
        Stats.addListener(stats);

        // When
        extAuto.registerAutomationJob(job1);
        extAuto.registerAutomationJob(job2);
        extAuto.registerAutomationJob(job3);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("Test Error")));
        assertThat(job1.wasRun(), is(equalTo(true)));
        assertThat(job2.wasRun(), is(equalTo(true)));
        assertThat(job3.wasRun(), is(equalTo(true)));

        assertThat(stats.getStat(ExtensionAutomation.WARNING_COUNT_STATS), is(equalTo(0L)));
        assertThat(stats.getStat(ExtensionAutomation.ERROR_COUNT_STATS), is(equalTo(1L)));
        assertThat(stats.getStat(ExtensionAutomation.PLANS_RUN_STATS), is(equalTo(1L)));
        assertThat(stats.getStat(ExtensionAutomation.TOTAL_JOBS_RUN_STATS), is(3L));
    }

    @Test
    void shouldContinuePlanOnWarning() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        String job1Name = "job1";
        String job2Name = "job2";
        String job3Name = "job3";

        AutomationJobImpl job1 =
                new AutomationJobImpl(true) {
                    @Override
                    public String getType() {
                        return job1Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        AutomationJobImpl job2 =
                new AutomationJobImpl(true) {
                    @Override
                    public String getType() {
                        return job2Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }

                    @Override
                    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
                        super.runJob(env, progress);
                        progress.warn("Test Warning");
                    }
                };
        AutomationJobImpl job3 =
                new AutomationJobImpl(true) {
                    @Override
                    public String getType() {
                        return job3Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        Path filePath = getResourcePath("resources/testplan-continueonwarning.yaml");
        InMemoryStats stats = new InMemoryStats();
        Stats.addListener(stats);

        // When
        extAuto.registerAutomationJob(job1);
        extAuto.registerAutomationJob(job2);
        extAuto.registerAutomationJob(job3);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(progress.getWarnings().get(0), is(equalTo("Test Warning")));
        assertThat(job1.wasRun(), is(equalTo(true)));
        assertThat(job2.wasRun(), is(equalTo(true)));
        assertThat(job3.wasRun(), is(equalTo(true)));

        assertThat(stats.getStat(ExtensionAutomation.WARNING_COUNT_STATS), is(equalTo(1L)));
        assertThat(stats.getStat(ExtensionAutomation.ERROR_COUNT_STATS), is(equalTo(0L)));
        assertThat(stats.getStat(ExtensionAutomation.PLANS_RUN_STATS), is(equalTo(1L)));
        assertThat(stats.getStat(ExtensionAutomation.TOTAL_JOBS_RUN_STATS), is(3L));
    }

    @Test
    void shouldRunPlanWithJobsWithSameType() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        String job1Name = "job1";

        AutomationJobImpl job =
                new AutomationJobImpl() {

                    @Override
                    public String getType() {
                        return job1Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        Path filePath = getResourcePath("resources/testplan-sametype.yaml");
        InMemoryStats stats = new InMemoryStats();
        Stats.addListener(stats);

        // When
        extAuto.registerAutomationJob(job);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());
        List<AutomationJob> runJobs = progress.getRunJobs();

        // Then
        assertThat(runJobs.size(), is(equalTo(3)));
        assertThat(runJobs.get(0).getName(), is(equalTo("job1")));
        assertThat(((AutomationJobImpl) runJobs.get(0)).getOptional(), is(equalTo("run 1")));
        assertThat(runJobs.get(1).getName(), is(equalTo("job1")));
        assertThat(((AutomationJobImpl) runJobs.get(1)).getOptional(), is(equalTo("run 2")));
        assertThat(runJobs.get(2).getName(), is(equalTo("job1")));
        assertThat(((AutomationJobImpl) runJobs.get(2)).getOptional(), is(nullValue()));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));

        assertThat(stats.getStat(ExtensionAutomation.WARNING_COUNT_STATS), is(equalTo(0L)));
        assertThat(stats.getStat(ExtensionAutomation.ERROR_COUNT_STATS), is(equalTo(0L)));
        assertThat(stats.getStat(ExtensionAutomation.PLANS_RUN_STATS), is(equalTo(1L)));
        assertThat(stats.getStat(ExtensionAutomation.TOTAL_JOBS_RUN_STATS), is(equalTo(3L)));
        assertThat(
                stats.getStat(
                        ExtensionAutomation.JOBS_RUN_STATS_PREFIX
                                + "job1"
                                + ExtensionAutomation.JOBS_RUN_STATS_POSTFIX),
                is(equalTo(3L)));
    }

    @Test
    void shouldReturnCmdLineArgs() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();

        // When
        CommandLineArgument[] args = extAuto.getCommandLineArguments();

        // Then
        assertThat(args.length, is(equalTo(4)));
        assertThat(args[0].getName(), is(equalTo("-autorun")));
        assertThat(args[0].getNumOfArguments(), is(equalTo(1)));
        assertThat(args[1].getName(), is(equalTo("-autogenmin")));
        assertThat(args[1].getNumOfArguments(), is(equalTo(1)));
        assertThat(args[2].getName(), is(equalTo("-autogenmax")));
        assertThat(args[2].getNumOfArguments(), is(equalTo(1)));
        assertThat(args[3].getName(), is(equalTo("-autogenconf")));
        assertThat(args[3].getNumOfArguments(), is(equalTo(1)));
    }

    @Test
    void shouldRunPlanWithWarnings() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        String job1Name = "job1";
        String job2Name = "job2";
        String job3Name = "job3";

        AutomationJobImpl job1 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job1Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        AutomationJobImpl job2 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job2Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        AutomationJobImpl job3 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job3Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        Path filePath = getResourcePath("resources/testplan-withwarnings.yaml");
        InMemoryStats stats = new InMemoryStats();
        Stats.addListener(stats);

        // When
        extAuto.registerAutomationJob(job1);
        extAuto.registerAutomationJob(job2);
        extAuto.registerAutomationJob(job3);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());
        List<AutomationJob> runJobs = progress.getRunJobs();

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(progress.getWarnings().get(0), is(equalTo("!automation.error.job.name!")));
        assertThat(progress.hasErrors(), is(equalTo(false)));

        assertThat(runJobs.size(), is(equalTo(3)));
        assertThat(runJobs.get(0).getName(), is(equalTo("Job 1")));
        assertThat(((AutomationJobImpl) runJobs.get(0)).wasRun(), is(equalTo(true)));
        assertThat(runJobs.get(1).getName(), is(equalTo("job2")));
        assertThat(((AutomationJobImpl) runJobs.get(1)).wasRun(), is(equalTo(true)));
        assertThat(runJobs.get(2).getName(), is(equalTo("job3")));
        assertThat(((AutomationJobImpl) runJobs.get(2)).wasRun(), is(equalTo(true)));

        assertThat(stats.getStat(ExtensionAutomation.WARNING_COUNT_STATS), is(equalTo(1L)));
        assertThat(stats.getStat(ExtensionAutomation.ERROR_COUNT_STATS), is(equalTo(0L)));
        assertThat(stats.getStat(ExtensionAutomation.PLANS_RUN_STATS), is(equalTo(1L)));
        assertThat(stats.getStat(ExtensionAutomation.TOTAL_JOBS_RUN_STATS), is(equalTo(3L)));
        assertThat(
                stats.getStat(
                        ExtensionAutomation.JOBS_RUN_STATS_PREFIX
                                + "job1"
                                + ExtensionAutomation.JOBS_RUN_STATS_POSTFIX),
                is(equalTo(1L)));
        assertThat(
                stats.getStat(
                        ExtensionAutomation.JOBS_RUN_STATS_PREFIX
                                + "job2"
                                + ExtensionAutomation.JOBS_RUN_STATS_POSTFIX),
                is(equalTo(1L)));
        assertThat(
                stats.getStat(
                        ExtensionAutomation.JOBS_RUN_STATS_PREFIX
                                + "job3"
                                + ExtensionAutomation.JOBS_RUN_STATS_POSTFIX),
                is(equalTo(1L)));
    }

    @Test
    void shouldFailPlanOnErrorApplyingParameters() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJobImpl job =
                new AutomationJobImpl(tpc) {
                    @Override
                    public String getType() {
                        return "job";
                    }

                    @Override
                    public Order getOrder() {
                        return Order.EXPLORE;
                    }

                    @Override
                    public String getParamMethodName() {
                        return "getTestParam";
                    }
                };
        ExtensionAutomation extAuto = new ExtensionAutomation();
        Path filePath = getResourcePath("resources/testPlan-failOnErrorApplyingParameters.yaml");

        // When
        extAuto.registerAutomationJob(job);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.options.badbool!")));
        assertThat(job.wasRun(), is(equalTo(false)));
    }

    @Test
    void shouldFailPlanOnWarningApplyingParameters() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJobImpl job =
                new AutomationJobImpl(tpc) {

                    @Override
                    public String getType() {
                        return "job";
                    }

                    @Override
                    public Order getOrder() {
                        return Order.EXPLORE;
                    }

                    @Override
                    public String getParamMethodName() {
                        return "getTestParam";
                    }
                };
        ExtensionAutomation extAuto = new ExtensionAutomation();
        Path filePath = getResourcePath("resources/testPlan-failOnWarningApplyingParameters.yaml");

        // When
        extAuto.registerAutomationJob(job);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.unknown!")));
        assertThat(job.wasRun(), is(equalTo(false)));
    }

    @Test
    void shouldExtractTests() {
        // Given
        AutomationJobImpl job =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return "job";
                    }
                };
        ExtensionAutomation extAuto = new ExtensionAutomation();
        Path filePath = getResourcePath("resources/testPlan-withTests.yaml");

        // When
        extAuto.registerAutomationJob(job);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());

        // Then
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.hasWarnings(), is(false));
        assertThat(progress.getRunJobs().size(), is(1));
        assertThat(((AutomationJobImpl) progress.getRunJobs().get(0)).testsAdded, is(true));
    }

    @Test
    void shouldFailPlanOnLoggedTestError() {
        // Given
        AutomationJobImpl job1 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return "job1";
                    }
                };

        AutomationJobImpl job2 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return "job2";
                    }
                };

        ExtensionAutomation extAuto = new ExtensionAutomation();
        Path filePath = getResourcePath("resources/testPlan-failOnLoggedTestError.yaml");
        job1.testsLogError = true;

        // When
        extAuto.registerAutomationJob(job1);
        extAuto.registerAutomationJob(job2);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());

        // Then
        assertThat(progress.getRunJobs().size(), is(1));
        assertThat(progress.getRunJobs().get(0).getType(), is(job1.getType()));
        assertThat(progress.hasWarnings(), is(false));
        assertThat(progress.hasErrors(), is(true));
        assertThat(
                progress.getErrors().get(0),
                is(((AutomationJobImpl) progress.getRunJobs().get(0)).testsLoggedString));
    }

    @Test
    void shouldReportNoRunningPlansByDefault() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();

        // When
        List<AutomationPlan> plans = extAuto.getRunningPlans();

        // Then
        assertThat(plans.size(), is(0));
    }

    @Test
    void shouldReportRunningPlan() throws Exception {
        // Given
        CountDownLatch startSignal = new CountDownLatch(1);
        AutomationJobLatchImpl job =
                new AutomationJobLatchImpl(startSignal) {
                    @Override
                    public String getType() {
                        return "job";
                    }
                };
        ExtensionAutomation extAuto = new ExtensionAutomation();
        Path filePath = getResourcePath("resources/testPlan-withTests.yaml");

        // When
        extAuto.registerAutomationJob(job);
        AutomationPlan plan = new AutomationPlan(extAuto, filePath.toFile());
        extAuto.runPlanAsync(plan);
        Thread.sleep(100);
        int count1 = extAuto.getRunningPlans().size();
        startSignal.countDown();
        Thread.sleep(100);
        int count2 = extAuto.getRunningPlans().size();

        // Then
        assertThat(count1, is(1));
        assertThat(count2, is(0));
    }

    @Test
    @Timeout(5)
    void shouldHandleRunJobExceptions() throws Exception {
        // Given
        var latch = new CountDownLatch(1);
        var job =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return "job";
                    }

                    @Override
                    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
                        throw new RuntimeException("Exception while running");
                    }

                    @Override
                    public void setTimeFinished() {
                        super.setTimeFinished();

                        latch.countDown();
                    }

                    @Override
                    public AutomationJob newJob() {
                        return this;
                    }
                };
        ExtensionAutomation extAuto = new ExtensionAutomation();
        Path filePath = getResourcePath("resources/testPlan-withTests.yaml");
        extAuto.registerAutomationJob(job);
        AutomationPlan plan = new AutomationPlan(extAuto, filePath.toFile());

        // When
        extAuto.runPlanAsync(plan);
        latch.await();

        // Then
        var progress = plan.getProgress();
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors(), contains("!automation.error.unexpected.internal!"));
    }

    @Test
    void shouldIgnoreDisabledJob() throws Exception {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        String job1Name = "job1";

        AutomationJobImpl job1 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job1Name;
                    }
                };

        String job2Name = "job2";
        AutomationJobImpl job2 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job2Name;
                    }
                };
        String job3Name = "job3";
        AutomationJobImpl job3 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job3Name;
                    }
                };
        Path filePath = getResourcePath("resources/testplan-withDisabledJob.yaml");
        InMemoryStats stats = new InMemoryStats();
        Stats.addListener(stats);
        extAuto.registerAutomationJob(job1);
        extAuto.registerAutomationJob(job2);
        extAuto.registerAutomationJob(job3);
        File f = new File(filePath.toAbsolutePath().toString());

        AutomationPlan plan = new AutomationPlan(extAuto, f);

        // When
        extAuto.runPlan(plan, false);
        AutomationProgress progress = plan.getProgress();

        List<AutomationJob> runJobs = progress.getRunJobs();

        // Then
        assertThat(plan.getJob(0).getStatus(), is(equalTo(AutomationJob.Status.NOT_ENABLED)));
        assertThat(runJobs.size(), is(equalTo(2)));
        assertThat(runJobs.get(0).getName(), is(equalTo("Job 2")));
        assertThat(runJobs.get(0).getStatus(), is(equalTo(AutomationJob.Status.COMPLETED)));
        assertThat(runJobs.get(1).getName(), is(equalTo("Job 3")));
        assertThat(runJobs.get(1).getStatus(), is(equalTo(AutomationJob.Status.COMPLETED)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldAlwaysRunJobOnError() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        String job1Name = "job1";
        String job2Name = "job2";
        String job3Name = "job3";

        AutomationJobImpl job1 =
                new AutomationJobImpl(true) {
                    @Override
                    public String getType() {
                        return job1Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }

                    @Override
                    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
                        super.runJob(env, progress);
                        progress.error("Test Error");
                    }
                };
        AutomationJobImpl job2 =
                new AutomationJobImpl(true) {
                    @Override
                    public String getType() {
                        return job2Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        AutomationJobImpl job3 =
                new AutomationJobImpl(true) {
                    @Override
                    public String getType() {
                        return job3Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        Path filePath = getResourcePath("resources/testplan-alwaysRunLastJob.yaml");
        InMemoryStats stats = new InMemoryStats();
        Stats.addListener(stats);

        // When
        extAuto.registerAutomationJob(job1);
        extAuto.registerAutomationJob(job2);
        extAuto.registerAutomationJob(job3);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("Test Error")));
        assertThat(job1.wasRun(), is(equalTo(true)));
        assertThat(job2.wasRun(), is(equalTo(false)));
        assertThat(job3.wasRun(), is(equalTo(true)));

        assertThat(stats.getStat(ExtensionAutomation.WARNING_COUNT_STATS), is(equalTo(0L)));
        assertThat(stats.getStat(ExtensionAutomation.ERROR_COUNT_STATS), is(equalTo(1L)));
        assertThat(stats.getStat(ExtensionAutomation.PLANS_RUN_STATS), is(equalTo(1L)));
        assertThat(stats.getStat(ExtensionAutomation.TOTAL_JOBS_RUN_STATS), is(2L));
    }

    // Methods are accessed via reflection
    @SuppressWarnings("unused")
    private static class TestParamContainer {

        private TestParam testParam = new TestParam();

        public TestParam getTestParam() {
            return testParam;
        }
    }

    // Methods are accessed via reflection
    @SuppressWarnings("unused")
    private static class TestParam {

        private boolean boolParam;
        private String stringParam;

        public void setBoolParam(boolean boolParam) {
            this.boolParam = boolParam;
        }

        public boolean getBoolParam() {
            return boolParam;
        }

        public void setStringParam(String stringParam) {
            this.stringParam = stringParam;
        }

        public String getStringParam() {
            return stringParam;
        }
    }

    private static class AutomationJobImpl extends AutomationJob {

        private boolean wasRun = false;
        private Object paramMethodObject;
        private String paramNameMethod = "getTestParam";
        private String optional;
        private String type;
        private Order order = Order.REPORT;
        private boolean testsAdded = false;
        private String testsLoggedString;
        private boolean testsLogError = false;
        private boolean returnOriginal = false;

        public AutomationJobImpl() {}

        public AutomationJobImpl(boolean returnOriginal) {
            this.returnOriginal = returnOriginal;
        }

        public AutomationJobImpl(String type) {
            this.type = type;
        }

        public AutomationJobImpl(Object paramMethodObject) {
            this.paramMethodObject = paramMethodObject;
        }

        @Override
        public void runJob(AutomationEnvironment env, AutomationProgress progress) {
            wasRun = true;
        }

        @Override
        protected void addTests(Object testsObj, AutomationProgress progress) {
            testsAdded = true;
        }

        @Override
        public void logTestsToProgress(AutomationProgress progress) {
            if (testsAdded && testsLogError) {
                testsLoggedString = RandomStringUtils.secure().nextAlphanumeric(20);
                progress.error(testsLoggedString);
            }
        }

        public boolean wasRun() {
            return wasRun;
        }

        @Override
        public String getType() {
            return type;
        }

        @Override
        public Order getOrder() {
            return order;
        }

        @Override
        public String getSummary() {
            return "";
        }

        @Override
        public Object getParamMethodObject() {
            return paramMethodObject;
        }

        @Override
        public String getParamMethodName() {
            return paramNameMethod;
        }

        @Override
        public boolean verifyCustomParameter(
                String name, String value, AutomationProgress progress) {
            if (name.equals("optional")) {
                return true;
            }
            return false;
        }

        @Override
        public boolean applyCustomParameter(String name, String value) {
            if (name.equals("optional")) {
                optional = value;
                return true;
            }
            return false;
        }

        public String getOptional() {
            return this.optional;
        }

        @Override
        public AutomationJob newJob() {
            if (returnOriginal) {
                return this;
            }
            AutomationJobImpl job = new AutomationJobImpl();
            job.paramMethodObject = this.paramMethodObject;
            job.type = this.getType();
            job.order = this.getOrder();
            job.testsLogError = testsLogError;
            return job;
        }
    }

    private static class AutomationJobLatchImpl extends AutomationJobImpl {

        private CountDownLatch latch;

        public AutomationJobLatchImpl(CountDownLatch latch) {
            super("job");
            this.latch = latch;
        }

        @Override
        public void runJob(AutomationEnvironment env, AutomationProgress progress) {
            try {
                latch.await();
            } catch (InterruptedException e) {
            }
            super.runJob(env, progress);
        }

        @Override
        public AutomationJob newJob() {
            return new AutomationJobLatchImpl(latch);
        }
    }
}
