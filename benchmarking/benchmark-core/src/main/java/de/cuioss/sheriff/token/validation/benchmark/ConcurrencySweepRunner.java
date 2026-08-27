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
import de.cuioss.sheriff.token.validation.benchmark.standard.SimpleCoreValidationBenchmark;
import de.cuioss.tools.logging.CuiLogger;
import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.results.format.ResultFormatFactory;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Integration.Jmh;

/**
 * Runs the core validation benchmark at multiple thread counts (1, 10, 50, 100)
 * to measure the RSA concurrency multiplier on HotSpot JVM.
 * <p>
 * This produces data directly comparable to the WRK connection sweep on native images,
 * answering whether the ~14x concurrency degradation is native-image-specific or
 * a fundamental RSA-under-concurrency issue.
 *
 * @author Oliver Wolff
 */
// cui-rewrite:disable CuiLogRecordPatternRecipe
// Diagnostic CLI tool — benchmark runners use direct logging for analysis output
public class ConcurrencySweepRunner {

    private static final CuiLogger LOGGER = new CuiLogger(ConcurrencySweepRunner.class);

    private static final int[] THREAD_COUNTS = {1, 10, 50, 100};
    private static final String OUTPUT_DIR = "target/benchmark-results/concurrency-sweep";

    public static void main(String[] args) throws IOException, RunnerException {
        // Initialize key cache
        BenchmarkKeyCache.initialize();

        Path outputPath = Path.of(OUTPUT_DIR);
        Files.createDirectories(outputPath);

        // Honor the same jmh.* system properties as the other runners (see BenchmarkConfiguration),
        // falling back to the sweep's previous hardcoded values when a property is not set.
        // Thread counts are the sweep dimension and are therefore not configurable here.
        int forks = Integer.getInteger(Jmh.FORKS, 1);
        int warmupIterations = Integer.getInteger(Jmh.WARMUP_ITERATIONS, 3);
        int measurementIterations = Integer.getInteger(Jmh.MEASUREMENT_ITERATIONS, 5);
        TimeValue measurementTime = BenchmarkConfiguration.parseTimeValue(System.getProperty(Jmh.MEASUREMENT_TIME, "4s"));
        TimeValue warmupTime = BenchmarkConfiguration.parseTimeValue(System.getProperty(Jmh.WARMUP_TIME, "1s"));

        List<RunResult> allResults = new ArrayList<>();

        for (int threads : THREAD_COUNTS) {
            LOGGER.info("Running concurrency sweep: %s threads", threads);

            Options options = new OptionsBuilder()
                    .include(SimpleCoreValidationBenchmark.class.getSimpleName() + "\\.measureAverageTime")
                    .forks(forks)
                    .warmupIterations(warmupIterations)
                    .measurementIterations(measurementIterations)
                    .measurementTime(measurementTime)
                    .warmupTime(warmupTime)
                    .threads(threads)
                    .jvmArgsPrepend(
                            "-Djava.util.logging.manager=java.util.logging.LogManager",
                            "-XX:+UnlockDiagnosticVMOptions",
                            "-XX:+DebugNonSafepoints"
                    )
                    .result(outputPath.resolve("sweep-" + threads + "t.json").toString())
                    .resultFormat(ResultFormatType.JSON)
                    .build();

            Collection<RunResult> results = new Runner(options).run();
            allResults.addAll(results);

            for (RunResult result : results) {
                double score = result.getPrimaryResult().getScore();
                String unit = result.getPrimaryResult().getScoreUnit();
                LOGGER.info("  %s threads: %s %s", threads, score, unit);
            }
        }

        // Write combined summary
        Path summaryFile = outputPath.resolve("concurrency-sweep-summary.json");
        try (PrintStream ps = new PrintStream(Files.newOutputStream(summaryFile))) {
            ResultFormatFactory.getInstance(ResultFormatType.JSON, ps).writeOut(allResults);
        }

        LOGGER.info("Concurrency sweep complete. Results in %s", OUTPUT_DIR);
    }
}
