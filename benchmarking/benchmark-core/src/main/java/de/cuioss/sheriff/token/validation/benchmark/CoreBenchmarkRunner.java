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
import org.openjdk.jmh.runner.RunnerException;

import java.io.IOException;

import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.INFO;

/**
 * Main class for running JWT validation core library micro benchmarks.
 * <p>
 * This class collects and runs all benchmark classes in the package.
 * It configures JMH with optimized settings for fast execution (&lt;10 minutes)
 * and produces a combined JSON report.
 * <p>
 * Optimized benchmark classes:
 * <ul>
 *   <li><strong>SimpleCoreValidationBenchmark</strong>: Essential validation performance metrics</li>
 *   <li><strong>SimpleErrorLoadBenchmark</strong>: Streamlined error handling scenarios</li>
 * </ul>
 */
public class CoreBenchmarkRunner extends AbstractBenchmarkRunner {

    private static final CuiLogger LOGGER = new CuiLogger(CoreBenchmarkRunner.class);

    @Override
    protected BenchmarkConfiguration createConfiguration() {
        // Configuration from Maven system properties:
        // - jmh.include: Pattern for benchmark classes to include
        // - jmh.forks, jmh.iterations, jmh.time, etc.: JMH execution parameters
        // Output directory is fixed: target/benchmark-results
        // Result file is auto-generated as: target/benchmark-results/micro-result.json
        
        return BenchmarkConfiguration.builder()
                .withBenchmarkType(BenchmarkType.MICRO)
                .withThroughputBenchmarkName("measureThroughput")  // SimpleCoreValidationBenchmark.measureThroughput
                .withLatencyBenchmarkName("measureAverageTime")    // SimpleCoreValidationBenchmark.measureAverageTime
                .withProjectName("Token-Sheriff")
                .build();
    }

    @Override
    protected void prepareBenchmark(BenchmarkConfiguration config) throws IOException {
        // Initialize key cache before benchmarks start
        BenchmarkKeyCache.initialize();
        LOGGER.info(INFO.JWT_BENCHMARKS_STARTING);
    }

    @Override
    protected void cleanup(BenchmarkConfiguration config) throws IOException {
        // No cleanup required for library benchmarks
        LOGGER.debug("Library benchmark cleanup completed");
    }

    /**
     * Main method to run all benchmarks.
     *
     * @param args command line arguments (not used)
     * @throws IOException if I/O operations fail
     * @throws RunnerException if benchmark execution fails
     */
    public static void main(String[] args) throws IOException, RunnerException {
        new CoreBenchmarkRunner().runBenchmark();
    }
}