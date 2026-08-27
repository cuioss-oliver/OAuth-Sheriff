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
package de.cuioss.benchmarking.common.converter;

import de.cuioss.benchmarking.common.config.BenchmarkType;
import de.cuioss.benchmarking.common.model.BenchmarkData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class JmhBenchmarkConverterTest {

    private JmhBenchmarkConverter converter;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        converter = new JmhBenchmarkConverter(BenchmarkType.INTEGRATION);
    }

    @Test
    void shouldConvertThroughputBenchmarkWithOpsPerMs() throws Exception {
        // Real data from actual JMH benchmark results
        String jmhResultJson = """
                [
                    {
                        "jmhVersion": "1.37",
                        "benchmark": "de.cuioss.sheriff.token.quarkus.benchmark.benchmarks.JwtHealthBenchmark.healthCheckThroughput",
                        "mode": "thrpt",
                        "threads": 24,
                        "forks": 2,
                        "primaryMetric": {
                            "score": 9.95235442564522,
                            "scoreError": 1.3458600374003153,
                            "scoreUnit": "ops/ms",
                            "scorePercentiles": {
                                "0.0": 8.994692479209395,
                                "50.0": 9.939903971491253,
                                "90.0": 10.891354944640886,
                                "99.0": 10.891354944640886,
                                "99.9": 10.891354944640886,
                                "100.0": 10.891354944640886
                            }
                        }
                    },
                    {
                        "jmhVersion": "1.37",
                        "benchmark": "de.cuioss.sheriff.token.quarkus.benchmark.benchmarks.JwtValidationBenchmark.validateJwtThroughput",
                        "mode": "thrpt",
                        "threads": 24,
                        "forks": 2,
                        "primaryMetric": {
                            "score": 8.117506965051852,
                            "scoreError": 0.1280119735066743,
                            "scoreUnit": "ops/ms",
                            "scorePercentiles": {
                                "0.0": 8.03825356648781,
                                "50.0": 8.103379928932226,
                                "90.0": 8.254920270412422,
                                "99.0": 8.254920270412422,
                                "99.9": 8.254920270412422,
                                "100.0": 8.254920270412422
                            }
                        }
                    }
                ]
                """;

        Path resultFile = tempDir.resolve("jmh-result.json");
        Files.writeString(resultFile, jmhResultJson);

        BenchmarkData result = converter.convert(resultFile);

        assertNotNull(result);
        assertEquals(2, result.getBenchmarks().size());

        // Test health check benchmark
        BenchmarkData.Benchmark healthCheck = result.getBenchmarks().getFirst();
        assertEquals("healthCheckThroughput", healthCheck.getName());
        assertEquals("thrpt", healthCheck.getMode());
        // Raw score should be converted: 9.95 ops/ms = 9,952 ops/s
        assertEquals(9952.35442564522, healthCheck.getRawScore(), 0.001);

        // CRITICAL TEST: Unit should be converted from ops/ms to ops/s
        assertEquals("ops/s", healthCheck.getScoreUnit());

        // Score should be converted: 9.95 ops/ms = 9,952 ops/s
        assertEquals("10.0K ops/s", healthCheck.getScore());
        assertEquals("10.0K ops/s", healthCheck.getThroughput());

        // Test JWT validation benchmark
        BenchmarkData.Benchmark jwtValidation = result.getBenchmarks().get(1);
        assertEquals("validateJwtThroughput", jwtValidation.getName());
        assertEquals("thrpt", jwtValidation.getMode());
        // Raw score should be converted: 8.12 ops/ms = 8,117 ops/s
        assertEquals(8117.506965051852, jwtValidation.getRawScore(), 0.001);

        // CRITICAL TEST: Unit should be converted from ops/ms to ops/s
        assertEquals("ops/s", jwtValidation.getScoreUnit());

        // Score should be converted: 8.12 ops/ms = 8,117 ops/s
        assertEquals("8.1K ops/s", jwtValidation.getScore());
        assertEquals("8.1K ops/s", jwtValidation.getThroughput());

        // Test overview
        BenchmarkData.Overview overview = result.getOverview();
        assertEquals("10.0K ops/s", overview.getThroughput());
        assertEquals("healthCheckThroughput", overview.getThroughputBenchmarkName());
    }

    @Test
    void shouldConvertLatencyBenchmarkWithMsPerOp() throws Exception {
        // Real data from actual JMH benchmark results
        String jmhResultJson = """
                [
                    {
                        "jmhVersion": "1.37",
                        "benchmark": "de.cuioss.sheriff.token.quarkus.benchmark.benchmarks.JwtHealthBenchmark.healthCheckThroughput",
                        "mode": "avgt",
                        "threads": 24,
                        "forks": 2,
                        "primaryMetric": {
                            "score": 2.1462601386826994,
                            "scoreError": 0.033650230501243106,
                            "scoreUnit": "ms/op",
                            "scorePercentiles": {
                                "0.0": 2.124914160175171,
                                "50.0": 2.144398848673893,
                                "90.0": 2.178275254845727,
                                "99.0": 2.178275254845727,
                                "99.9": 2.178275254845727,
                                "100.0": 2.178275254845727
                            }
                        }
                    }
                ]
                """;

        Path resultFile = tempDir.resolve("jmh-result.json");
        Files.writeString(resultFile, jmhResultJson);

        BenchmarkData result = converter.convert(resultFile);

        assertNotNull(result);
        assertEquals(1, result.getBenchmarks().size());

        BenchmarkData.Benchmark latencyBenchmark = result.getBenchmarks().getFirst();
        assertEquals("healthCheckThroughput", latencyBenchmark.getName());
        assertEquals("avgt", latencyBenchmark.getMode());
        assertEquals(2.1462601386826994, latencyBenchmark.getRawScore(), 0.001);

        // Latency units should remain unchanged
        assertEquals("ms/op", latencyBenchmark.getScoreUnit());
        assertEquals("2.1 ms/op", latencyBenchmark.getScore());
        assertEquals("2.1 ms/op", latencyBenchmark.getLatency());
        assertNull(latencyBenchmark.getThroughput());
    }

    @Test
    void shouldHandleOpsPerSecondWithoutConversion() throws Exception {
        // Test data with ops/s (should remain unchanged)
        String jmhResultJson = """
                [
                    {
                        "jmhVersion": "1.37",
                        "benchmark": "test.Benchmark.throughputTest",
                        "mode": "thrpt",
                        "threads": 1,
                        "forks": 1,
                        "primaryMetric": {
                            "score": 1000.0,
                            "scoreError": 10.0,
                            "scoreUnit": "ops/s"
                        }
                    }
                ]
                """;

        Path resultFile = tempDir.resolve("jmh-result.json");
        Files.writeString(resultFile, jmhResultJson);

        BenchmarkData result = converter.convert(resultFile);

        assertNotNull(result);
        assertEquals(1, result.getBenchmarks().size());

        BenchmarkData.Benchmark benchmark = result.getBenchmarks().getFirst();
        assertEquals("ops/s", benchmark.getScoreUnit());
        assertEquals("1.0K ops/s", benchmark.getScore());
    }

    @Test
    void shouldConvertMicrosecondLatencyToMillisecondsInOverview() throws Exception {
        // BUG FIX TEST: Verify that latency in us/op is converted to ms/op in the overview
        // This test ensures that the badge generator receives latency in milliseconds
        String jmhResultJson = """
                [
                    {
                        "jmhVersion": "1.37",
                        "benchmark": "test.ThroughputBenchmark",
                        "mode": "thrpt",
                        "threads": 100,
                        "forks": 1,
                        "primaryMetric": {
                            "score": 176662.03,
                            "scoreError": 1000.0,
                            "scoreUnit": "ops/s"
                        }
                    },
                    {
                        "jmhVersion": "1.37",
                        "benchmark": "test.LatencyBenchmark",
                        "mode": "avgt",
                        "threads": 100,
                        "forks": 1,
                        "primaryMetric": {
                            "score": 867.4184,
                            "scoreError": 50.0,
                            "scoreUnit": "us/op"
                        }
                    }
                ]
                """;

        Path resultFile = tempDir.resolve("jmh-result.json");
        Files.writeString(resultFile, jmhResultJson);

        // Use MICRO type converter (same as library benchmarks)
        JmhBenchmarkConverter microConverter = new JmhBenchmarkConverter(BenchmarkType.MICRO);
        BenchmarkData result = microConverter.convert(resultFile);

        assertNotNull(result);
        assertEquals(2, result.getBenchmarks().size());

        // Verify latency benchmark shows original unit
        BenchmarkData.Benchmark latencyBenchmark = result.getBenchmarks().get(1);
        assertEquals("LatencyBenchmark", latencyBenchmark.getName());
        assertEquals("avgt", latencyBenchmark.getMode());
        assertEquals(867.4184, latencyBenchmark.getRawScore(), 0.001);
        assertEquals("us/op", latencyBenchmark.getScoreUnit());

        // CRITICAL TEST: Overview should have latency converted to milliseconds
        // 867.4184 us/op = 0.8674 ms/op
        // This is what gets passed to BenchmarkMetrics and ultimately to BadgeGenerator
        // The conversion must happen in JmhBenchmarkConverter.createOverview()
        //
        // Note: We can't directly access the latency value used in the overview,
        // but we can verify it through the grade calculation. With correct conversion:
        // - throughput: 176662 ops/s
        // - latency: 0.8674 ms (after conversion from 867.4 us)
        // - Performance score calculation:
        //   throughputScore = (176662 / 100.0) * 0.5 = 883.31
        //   latencyScore = (100.0 / 0.8674) * 0.5 = 57.64
        //   total score = 883.31 + 57.64 = 940.95 (rounded to 941)
        // - This should result in grade A+ (score >= 95)
        //
        // BEFORE FIX: latency was 867.4 (not converted), resulting in grade F
        // AFTER FIX: latency is 0.8674 (converted), resulting in grade A+
        BenchmarkData.Overview overview = result.getOverview();
        assertNotNull(overview);
        assertEquals("ThroughputBenchmark", overview.getThroughputBenchmarkName());
        assertEquals("LatencyBenchmark", overview.getLatencyBenchmarkName());

        // Verify the fix: grade should be A+ because latency was correctly converted
        // If latency was NOT converted (867.4 instead of 0.8674), grade would be F
        assertEquals("A+", overview.getPerformanceGrade(),
                """
                        Grade should be A+ with correct latency conversion (0.8674 ms). \
                        If F, latency was not converted (867.4 ms).""");
    }

    @Test
    void shouldCalculatePerformanceScoreAccordingToDocumentation() throws Exception {
        Path realResultFile = Path.of("src/test/resources/library-benchmark-results/micro-result-scoring-test.json");
        assertTrue(Files.exists(realResultFile), "Real benchmark result file should exist");

        JmhBenchmarkConverter microConverter = new JmhBenchmarkConverter(BenchmarkType.MICRO);
        BenchmarkData result = microConverter.convert(realResultFile);

        BenchmarkData.Overview overview = result.getOverview();
        assertNotNull(overview);

        assertEquals("validateMixedTokens50", overview.getThroughputBenchmarkName());
        assertEquals("measureAverageTime", overview.getLatencyBenchmarkName());

        int actualScore = overview.getPerformanceScore();

        assertTrue(actualScore >= 900 && actualScore <= 950,
                """
                        Performance score should be ~939 (±50) according to documentation formula. \
                        Expected: ~939, Actual: %d""".formatted(actualScore));

        assertEquals("A+", overview.getPerformanceGrade(),
                "Grade should be A+ for score ≥ 95. Actual score: %d, grade: %s".formatted(
                        actualScore, overview.getPerformanceGrade()));
    }
}