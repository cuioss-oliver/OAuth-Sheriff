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

import de.cuioss.benchmarking.common.model.BenchmarkData;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link WrkBenchmarkConverter}, focusing on honest reporting:
 * no fabricated percentiles and no silent zero-metrics for unparseable files.
 */
class WrkBenchmarkConverterTest {

    private static final String WRK_OUTPUT = """
            === BENCHMARK METADATA ===
            benchmark_name: jwtValidation
            start_time: 1700000000
            === WRK OUTPUT ===

            Running 10s test @ https://localhost:10443/jwt/validate
              4 threads and 20 connections
              Thread Stats   Avg      Stdev     Max   +/- Stdev
                Latency     2.00ms    1.00ms   20.00ms   90.00%
                Req/Sec     5.00k   1.00k    10.00k    75.00%
              Latency Distribution
                 50%    1.50ms
                 75%    2.50ms
                 90%    4.00ms
                 99%    9.00ms
              100000 requests in 10.00s, 50.00MB read
            Requests/sec:  10000.00
            Transfer/sec:      5.00MB
            """;

    private final WrkBenchmarkConverter converter = new WrkBenchmarkConverter();

    @Test
    void shouldOnlyReportMeasuredPercentiles(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("wrk-jwt-results.txt");
        Files.writeString(file, WRK_OUTPUT);

        BenchmarkData data = converter.convert(file);

        assertEquals(1, data.getBenchmarks().size());
        Map<String, Double> percentiles = data.getBenchmarks().getFirst().getPercentiles();

        // Only the percentiles actually measured by wrk are reported
        assertEquals(Set.of("50.0", "75.0", "90.0", "99.0"), percentiles.keySet(),
                "No fabricated percentiles: only measured keys may be present");
        assertEquals(1.5, percentiles.get("50.0"));
        assertEquals(9.0, percentiles.get("99.0"));
    }

    @Test
    void shouldUseMeasuredP50ForOverviewLatency(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("wrk-jwt-results.txt");
        Files.writeString(file, WRK_OUTPUT);

        BenchmarkData data = converter.convert(file);

        assertEquals(1.5, data.getOverview().getLatencyMs(),
                "Overview latency must use the measured P50");
    }

    @Test
    void shouldFallBackToAverageLatencyWhenP50Missing(@TempDir Path tempDir) throws Exception {
        // wrk output without a latency distribution section (e.g. --latency flag missing)
        String withoutDistribution = """
                === WRK OUTPUT ===
                Running 10s test @ https://localhost:10443/jwt/validate
                  4 threads and 20 connections
                  Thread Stats   Avg      Stdev     Max   +/- Stdev
                    Latency     2.00ms    1.00ms   20.00ms   90.00%
                Requests/sec:  10000.00
                """;
        Path file = tempDir.resolve("wrk-jwt-results.txt");
        Files.writeString(file, withoutDistribution);

        BenchmarkData data = converter.convert(file);

        assertEquals(1, data.getBenchmarks().size());
        assertTrue(data.getBenchmarks().getFirst().getPercentiles().isEmpty(),
                "No percentiles may be fabricated");
        assertEquals(2.0, data.getOverview().getLatencyMs(),
                "Overview latency must fall back to the wrk-reported average latency");
    }

    @Test
    void shouldSkipFilesWithoutParseableThroughput(@TempDir Path tempDir) throws Exception {
        Path wrkDir = tempDir.resolve("wrk");
        Files.createDirectories(wrkDir);
        Files.writeString(wrkDir.resolve("wrk-jwt-results.txt"),
                "=== WRK OUTPUT ===\ncompletely unparseable garbage\n");

        BenchmarkData data = converter.convert(wrkDir);

        assertTrue(data.getBenchmarks().isEmpty(),
                "Files without a Requests/sec line must be skipped, not reported as zero");
        assertEquals("F", data.getOverview().getPerformanceGrade());
    }

    @Test
    void shouldSkipUnparseableSingleFile(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("wrk-jwt-results.txt");
        Files.writeString(file, "no wrk content at all");

        BenchmarkData data = converter.convert(file);

        assertTrue(data.getBenchmarks().isEmpty(),
                "Unparseable file must yield no benchmark instead of zero-metrics");
    }
}
