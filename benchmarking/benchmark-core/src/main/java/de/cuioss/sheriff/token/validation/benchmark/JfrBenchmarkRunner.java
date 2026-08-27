/*
 * Copyright © 2025-present CUI-OpenSource-Software (info@cuioss.de)
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
package de.cuioss.sheriff.token.validation.benchmark;

import de.cuioss.benchmarking.common.config.BenchmarkConfiguration;
import de.cuioss.benchmarking.common.config.BenchmarkType;
import de.cuioss.benchmarking.common.runner.AbstractBenchmarkRunner;
import de.cuioss.tools.logging.CuiLogger;
import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;

import java.io.File;
import java.io.IOException;
import java.util.Collection;

import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.INFO;

/**
 * JFR-enabled benchmark runner for JWT validation performance analysis with variance metrics.
 * <p>
 * This runner specifically executes the JFR-instrumented benchmarks that capture:
 * <ul>
 *   <li>Individual operation timing with metadata</li>
 *   <li>Periodic statistics including variance</li>
 *   <li>Concurrent operation tracking</li>
 * </ul>
 * <p>
 * To run: {@code mvn verify -Pbenchmark-jfr}
 * <p>
 * JFR data is automatically saved to: {@code target/benchmark-jfr-results/}
 *
 * @see de.cuioss.sheriff.token.validation.benchmark.jfr.benchmarks.CoreJfrBenchmark
 * @see de.cuioss.sheriff.token.validation.benchmark.jfr.benchmarks.ErrorJfrBenchmark
 * @see de.cuioss.sheriff.token.validation.benchmark.jfr.benchmarks.MixedJfrBenchmark
 */
public class JfrBenchmarkRunner extends AbstractBenchmarkRunner {

    private static final CuiLogger LOGGER = new CuiLogger(JfrBenchmarkRunner.class);
    private static final String RESULTS_DIR = "target/benchmark-jfr-results";

    @Override
    protected BenchmarkConfiguration createConfiguration() {
        return BenchmarkConfiguration.builder()
                .withBenchmarkType(BenchmarkType.MICRO)
                .withThroughputBenchmarkName("measureThroughput")  // JFR benchmarks also measure throughput
                .withLatencyBenchmarkName("measureAverageTime")    // JFR benchmarks also measure latency
                .withProjectName("Token-Sheriff")
                .withIncludePattern("de\\.cuioss\\.sheriff\\.token\\.validation\\.benchmark\\.jfr\\.benchmarks\\..*")
                .withForks(1)
                .withWarmupIterations(5)
                .withMeasurementIterations(5)
                .withMeasurementTime(TimeValue.seconds(5))
                .withWarmupTime(TimeValue.seconds(3))
                .withThreads(16)
                .withResultFile(getJfrResultFile())
                .withResultsDirectory(RESULTS_DIR)
                .build();
    }

    @Override
    protected void prepareBenchmark(BenchmarkConfiguration config) throws IOException {
        // Initialize key cache before benchmarks start
        BenchmarkKeyCache.initialize();
        LOGGER.info(INFO.JFR_BENCHMARKS_STARTING);
        LOGGER.info(INFO.JFR_RECORDING_PATH, config.resultsDirectory(), "/jfr-benchmark.jfr");
    }

    @Override
    protected OptionsBuilder buildCommonOptions(BenchmarkConfiguration config) {
        // Get base options from parent
        OptionsBuilder builder = super.buildCommonOptions(config);

        // Add JFR-specific JVM arguments
        builder.jvmArgs("-XX:+UnlockDiagnosticVMOptions",
                "-XX:+DebugNonSafepoints",
                "-XX:StartFlightRecording=filename=" + config.resultsDirectory() + "/jfr-benchmark.jfr,settings=profile",
                "-Djava.util.logging.config.file=benchmark-logging.properties",
                "-Dbenchmark.results.dir=" + config.resultsDirectory());

        return builder;
    }

    @Override
    protected void afterBenchmark(Collection<RunResult> results, BenchmarkConfiguration config) {
        LOGGER.info(INFO.JFR_BENCHMARK_COMPLETED);
        LOGGER.info(INFO.JFR_VARIANCE_COMMAND, config.resultsDirectory(), "/jfr-benchmark.jfr");
    }

    @Override
    protected void cleanup(BenchmarkConfiguration config) throws IOException {
        // No special cleanup required for JFR benchmarks
        LOGGER.debug("JFR benchmark cleanup completed");
    }

    /**
     * Gets the JFR-specific result file.
     * 
     * @return the JFR result file path
     */
    private static String getJfrResultFile() {
        String resultFile = RESULTS_DIR + "/micro-result.json";
        File file = new File(resultFile);
        File parentDir = file.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }
        return resultFile;
    }

    /**
     * Main method to run JFR-instrumented benchmarks.
     *
     * @param args command line arguments (not used)
     * @throws IOException if I/O operations fail
     * @throws RunnerException if benchmark execution fails
     */
    public static void main(String[] args) throws IOException, RunnerException {
        new JfrBenchmarkRunner().runBenchmark();
    }
}