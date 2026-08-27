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
package de.cuioss.benchmarking.common.runner;

import de.cuioss.benchmarking.common.config.BenchmarkConfiguration;
import de.cuioss.tools.logging.CuiLogger;
import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.INFO.BENCHMARKS_COMPLETED_WITH_ARTIFACTS;
import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.INFO.BENCHMARK_RUNNER_STARTING_WITH_DETAILS;
import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.WARN.SECRET_PROPERTY_ON_FORK_COMMAND_LINE;

/**
 * Abstract base class for JMH benchmark runners that integrates with CUI benchmarking infrastructure.
 * <p>
 * This runner uses the Template Method pattern to orchestrate benchmark execution while
 * allowing concrete implementations to customize specific steps.
 * <p>
 * The template method {@link #runBenchmark()} defines the benchmark execution flow:
 * <ol>
 *   <li>Validation of configuration</li>
 *   <li>Preparation phase ({@link #prepareBenchmark(BenchmarkConfiguration)})</li>
 *   <li>Benchmark execution ({@link #executeBenchmark(Options)})</li>
 *   <li>Results processing ({@link #processResults(Collection, BenchmarkConfiguration)})</li>
 *   <li>Cleanup phase ({@link #cleanup(BenchmarkConfiguration)})</li>
 * </ol>
 * <p>
 * Features:
 * <ul>
 *   <li>Smart benchmark type detection (micro vs integration)</li>
 *   <li>Automatic badge generation with performance scoring</li>
 *   <li>Self-contained HTML reports with embedded CSS</li>
 *   <li>GitHub Pages ready deployment structure</li>
 *   <li>Structured metrics in JSON format</li>
 * </ul>
 */
public abstract class AbstractBenchmarkRunner {

    private static final CuiLogger LOGGER =
            new CuiLogger(AbstractBenchmarkRunner.class);

    /**
     * Prefixes of system properties that are forwarded to forked benchmark JVMs.
     */
    private static final List<String> FORWARDED_PROPERTY_PREFIXES = List.of(
            "jmh.", "benchmark.", "token.", "integration.", "quarkus.", "javax.net.ssl.");

    /**
     * Known secret-bearing property keys. They may be required by the forked JVM,
     * so they are forwarded when set, but a warning is emitted because they appear
     * on the fork command line.
     */
    private static final Set<String> SECRET_PROPERTY_KEYS = Set.of(
            "token.keycloak.password", "token.keycloak.clientSecret");

    /**
     * Creates the benchmark configuration for this runner.
     * This method must provide a complete configuration including:
     * - Benchmark type
     * - Include pattern
     * - Result file name and directory
     * - Throughput and latency benchmark names
     * - Any other specific configuration
     *
     * @return the complete benchmark configuration
     */
    protected abstract BenchmarkConfiguration createConfiguration();

    /**
     * Prepares the benchmark environment.
     * This method is called after configuration validation and before benchmark execution.
     * Use this for initialization tasks like:
     * - Setting up resources
     * - Initializing caches
     * - Configuring logging
     *
     * @param config the benchmark configuration
     * @throws IOException if preparation fails
     */
    protected abstract void prepareBenchmark(BenchmarkConfiguration config) throws IOException;

    /**
     * Executes the benchmark with the given options.
     * Default implementation uses JMH Runner, but can be overridden for custom execution.
     *
     * @param options the JMH options
     * @return collection of benchmark results
     * @throws RunnerException if benchmark execution fails
     */
    protected Collection<RunResult> executeBenchmark(Options options) throws RunnerException {
        return new Runner(options).run();
    }

    /**
     * Processes the benchmark results.
     * Default implementation uses BenchmarkResultProcessor.
     *
     * @param results the benchmark results
     * @param config the benchmark configuration
     * @throws IOException if processing fails
     */
    protected void processResults(Collection<RunResult> results, BenchmarkConfiguration config) throws IOException {
        // Process results (generates reports and GitHub Pages)
        BenchmarkResultProcessor processor = new BenchmarkResultProcessor(
                config.reportConfig().benchmarkType(),
                config.reportConfig()
        );
        processor.processResults(results, config.resultsDirectory());
    }

    /**
     * Performs cleanup after benchmark execution.
     * This method is called after results processing, regardless of success or failure.
     * Use this for:
     * - Releasing resources
     * - Final metrics collection
     * - Post-processing tasks
     *
     * @param config the benchmark configuration
     * @throws IOException if cleanup fails
     */
    protected abstract void cleanup(BenchmarkConfiguration config) throws IOException;

    /**
     * Hook method called before benchmark execution starts.
     * Override to add custom pre-benchmark logic.
     *
     * @param config the benchmark configuration
     */
    protected void beforeBenchmark(BenchmarkConfiguration config) {
        LOGGER.debug("Benchmark execution starting");
    }

    /**
     * Hook method called after benchmark execution completes.
     * Override to add custom post-benchmark logic.
     *
     * @param results the benchmark results
     * @param config the benchmark configuration
     */
    protected void afterBenchmark(Collection<RunResult> results, BenchmarkConfiguration config) {
        LOGGER.debug("Benchmark execution completed with %s results", results.size());
    }

    /**
     * Builds JMH options from the benchmark configuration.
     * This method extracts common option building logic that can be reused or extended.
     *
     * @param config the benchmark configuration
     * @return JMH options builder with common settings applied
     */
    protected OptionsBuilder buildCommonOptions(BenchmarkConfiguration config) {
        var builder = new OptionsBuilder();

        builder.include(config.includePattern())
                .resultFormat(config.reportConfig().resultFormat())
                .result(config.reportConfig().getOrCreateResultFile())
                .forks(config.forks())
                .warmupIterations(config.warmupIterations())
                .measurementIterations(config.measurementIterations())
                .measurementTime(config.measurementTime())
                .warmupTime(config.warmupTime())
                .threads(config.threads());

        // Forward only an explicit allowlist of benchmark-related system properties to forked
        // JVMs. Forwarding EVERY parent property would leak arbitrary values (including
        // credentials) onto the fork command line, visible in process listings and CI logs.
        var systemProperties = System.getProperties().entrySet().stream()
                .filter(e -> isForwardedProperty(String.valueOf(e.getKey())))
                .map(e -> "-D" + e.getKey() + "=" + e.getValue())
                .toArray(String[]::new);

        builder.jvmArgsPrepend(systemProperties);

        return builder;
    }

    private static boolean isForwardedProperty(String key) {
        if (FORWARDED_PROPERTY_PREFIXES.stream().noneMatch(key::startsWith)) {
            return false;
        }
        String lowerKey = key.toLowerCase(Locale.ROOT);
        if (SECRET_PROPERTY_KEYS.contains(key)
                || lowerKey.contains("password")
                || lowerKey.contains("secret")
                || lowerKey.contains("credential")
                || lowerKey.contains("private")) {
            LOGGER.warn(SECRET_PROPERTY_ON_FORK_COMMAND_LINE, key);
        }
        return true;
    }

    /**
     * Validates the benchmark configuration.
     * Throws IllegalArgumentException if configuration is invalid.
     *
     * @param config the configuration to validate
     * @throws IllegalArgumentException if configuration is invalid
     */
    protected void validateConfiguration(BenchmarkConfiguration config) {
        if (config == null) {
            throw new IllegalArgumentException("Benchmark configuration cannot be null");
        }

        if (config.benchmarkType() == null) {
            throw new IllegalArgumentException("Benchmark type must be specified");
        }

        if (config.includePattern() == null || config.includePattern().isEmpty()) {
            throw new IllegalArgumentException("Include pattern must be specified");
        }

        if (config.resultsDirectory() == null || config.resultsDirectory().isEmpty()) {
            throw new IllegalArgumentException("Results directory must be specified");
        }

        if (config.forks() < 0) {
            throw new IllegalArgumentException("Forks must be non-negative");
        }

        if (config.warmupIterations() < 0) {
            throw new IllegalArgumentException("Warmup iterations must be non-negative");
        }

        if (config.measurementIterations() <= 0) {
            throw new IllegalArgumentException("Measurement iterations must be positive");
        }

        if (config.threads() <= 0) {
            throw new IllegalArgumentException("Threads must be positive");
        }
    }

    /**
     * Template method that defines the benchmark execution flow.
     * This is the main entry point that orchestrates all phases of benchmark execution.
     *
     * @throws IOException if I/O operations fail
     * @throws RunnerException if benchmark execution fails
     */
    public final void runBenchmark() throws IOException, RunnerException {
        // Step 1: Create and validate configuration
        BenchmarkConfiguration config = createConfiguration();
        validateConfiguration(config);

        String outputDir = config.resultsDirectory();
        LOGGER.info(BENCHMARK_RUNNER_STARTING_WITH_DETAILS, config.benchmarkType(), outputDir);

        // Step 2: Ensure output directory exists
        Path outputPath = Path.of(outputDir);
        Files.createDirectories(outputPath);

        try {
            // Step 3: Preparation phase
            prepareBenchmark(config);

            // Step 4: Pre-benchmark hook
            beforeBenchmark(config);

            // Step 5: Build options
            Options options = buildCommonOptions(config).build();

            // Step 6: Execute benchmarks
            Collection<RunResult> results = executeBenchmark(options);

            if (results.isEmpty()) {
                throw new IllegalStateException("No benchmark results produced");
            }

            // Step 7: Process results
            processResults(results, config);

            // Step 8: Post-benchmark hook
            afterBenchmark(results, config);

            LOGGER.info(BENCHMARKS_COMPLETED_WITH_ARTIFACTS, results.size(), outputDir);

        } finally {
            // Step 9: Cleanup (always executed)
            cleanup(config);
        }
    }

}