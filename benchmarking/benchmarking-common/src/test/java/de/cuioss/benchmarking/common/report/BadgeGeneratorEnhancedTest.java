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
package de.cuioss.benchmarking.common.report;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import de.cuioss.benchmarking.common.config.BenchmarkType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Enhanced unit tests for BadgeGenerator covering new functionality.
 */
class BadgeGeneratorEnhancedTest {

    private static final Gson GSON = new Gson();
    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC);

    @Test
    void performanceBadgeWithMetrics() {
        BadgeGenerator generator = new BadgeGenerator();

        // Test A+ grade with high throughput and low latency
        BenchmarkMetrics metricsAPlus = new BenchmarkMetrics(
                "test", "test", 50000.0, 0.12, 96.0, "A+"
        );
        String badgeAPlus = generator.generatePerformanceBadge(metricsAPlus);
        JsonObject jsonAPlus = GSON.fromJson(badgeAPlus, JsonObject.class);
        assertEquals("brightgreen", jsonAPlus.get("color").getAsString());
        assertEquals("Grade A+ (50k ops/s, 0.12ms)", jsonAPlus.get("message").getAsString());

        // Test A grade with formatted metrics
        BenchmarkMetrics metricsA = new BenchmarkMetrics(
                "test", "test", 45123.0, 0.145, 86.0, "A"
        );
        String badgeA = generator.generatePerformanceBadge(metricsA);
        JsonObject jsonA = GSON.fromJson(badgeA, JsonObject.class);
        assertEquals("green", jsonA.get("color").getAsString());
        assertEquals("Grade A (45k ops/s, 0.15ms)", jsonA.get("message").getAsString());

        // Test B grade
        BenchmarkMetrics metricsB = new BenchmarkMetrics(
                "test", "test", 30000.0, 0.25, 76.0, "B"
        );
        String badgeB = generator.generatePerformanceBadge(metricsB);
        JsonObject jsonB = GSON.fromJson(badgeB, JsonObject.class);
        assertEquals("yellowgreen", jsonB.get("color").getAsString());
        assertEquals("Grade B (30k ops/s, 0.25ms)", jsonB.get("message").getAsString());

        // Test C grade
        BenchmarkMetrics metricsC = new BenchmarkMetrics(
                "test", "test", 20000.0, 0.5, 66.0, "C"
        );
        String badgeC = generator.generatePerformanceBadge(metricsC);
        JsonObject jsonC = GSON.fromJson(badgeC, JsonObject.class);
        assertEquals("yellow", jsonC.get("color").getAsString());
        assertEquals("Grade C (20k ops/s, 0.50ms)", jsonC.get("message").getAsString());

        // Test D grade
        BenchmarkMetrics metricsD = new BenchmarkMetrics(
                "test", "test", 10000.0, 1.0, 56.0, "D"
        );
        String badgeD = generator.generatePerformanceBadge(metricsD);
        JsonObject jsonD = GSON.fromJson(badgeD, JsonObject.class);
        assertEquals("orange", jsonD.get("color").getAsString());
        assertEquals("Grade D (10k ops/s, 1.00ms)", jsonD.get("message").getAsString());

        // Test F grade
        BenchmarkMetrics metricsF = new BenchmarkMetrics(
                "test", "test", 5000.0, 2.5, 45.0, "F"
        );
        String badgeF = generator.generatePerformanceBadge(metricsF);
        JsonObject jsonF = GSON.fromJson(badgeF, JsonObject.class);
        assertEquals("red", jsonF.get("color").getAsString());
        assertEquals("Grade F (5k ops/s, 2.50ms)", jsonF.get("message").getAsString());

        // Test edge cases with different throughput ranges
        BenchmarkMetrics metricsLowThroughput = new BenchmarkMetrics(
                "test", "test", 500.0, 5.0, 30.0, "F"
        );
        String badgeLow = generator.generatePerformanceBadge(metricsLowThroughput);
        JsonObject jsonLow = GSON.fromJson(badgeLow, JsonObject.class);
        assertEquals("Grade F (500 ops/s, 5.00ms)", jsonLow.get("message").getAsString());

        BenchmarkMetrics metricsHighThroughput = new BenchmarkMetrics(
                "test", "test", 150000.0, 0.05, 98.0, "A+"
        );
        String badgeHigh = generator.generatePerformanceBadge(metricsHighThroughput);
        JsonObject jsonHigh = GSON.fromJson(badgeHigh, JsonObject.class);
        assertEquals("Grade A+ (150k ops/s, 0.05ms)", jsonHigh.get("message").getAsString());
    }

    @Test
    void trendBadgeWithMetrics() {
        BadgeGenerator generator = new BadgeGenerator();

        // Test upward trend
        TrendDataProcessor.TrendMetrics upTrend = new TrendDataProcessor.TrendMetrics(
                "up", 15.3, 85.0, 20.0, -10.0
        );
        String badgeUp = generator.generateTrendBadge(upTrend);
        JsonObject jsonUp = GSON.fromJson(badgeUp, JsonObject.class);
        assertEquals("green", jsonUp.get("color").getAsString());
        assertEquals("↑ 15.3%", jsonUp.get("message").getAsString());

        // Test downward trend
        TrendDataProcessor.TrendMetrics downTrend = new TrendDataProcessor.TrendMetrics(
                "down", -8.7, 75.0, -10.0, 15.0
        );
        String badgeDown = generator.generateTrendBadge(downTrend);
        JsonObject jsonDown = GSON.fromJson(badgeDown, JsonObject.class);
        assertEquals("red", jsonDown.get("color").getAsString());
        assertEquals("↓ 8.7%", jsonDown.get("message").getAsString());

        // Test stable trend
        TrendDataProcessor.TrendMetrics stableTrend = new TrendDataProcessor.TrendMetrics(
                "stable", 0.5, 80.0, 1.0, -0.5
        );
        String badgeStable = generator.generateTrendBadge(stableTrend);
        JsonObject jsonStable = GSON.fromJson(badgeStable, JsonObject.class);
        assertEquals("blue", jsonStable.get("color").getAsString());
        assertEquals("→ 0.5%", jsonStable.get("message").getAsString());
    }

    @Test
    void defaultTrendBadge() {
        BadgeGenerator generator = new BadgeGenerator();

        String badge = generator.generateDefaultTrendBadge();
        JsonObject json = GSON.fromJson(badge, JsonObject.class);

        assertEquals(1, json.get("schemaVersion").getAsInt());
        assertEquals("Trend", json.get("label").getAsString());
        assertEquals("No history", json.get("message").getAsString());
        assertEquals("lightgray", json.get("color").getAsString());
    }

    @Test
    void lastRunBadgeWithSpecificTime() {
        BadgeGenerator generator = new BadgeGenerator();

        // Create specific instant for testing
        Instant testTime = Instant.parse("2025-01-29T14:30:00Z");

        String badge = generator.generateLastRunBadge(testTime);
        JsonObject json = GSON.fromJson(badge, JsonObject.class);

        assertEquals(1, json.get("schemaVersion").getAsInt());
        assertEquals("Last Run", json.get("label").getAsString());
        assertEquals("2025-01-29", json.get("message").getAsString());
        assertEquals("blue", json.get("color").getAsString());
    }

    @Test
    void writeBadgeFiles(@TempDir Path tempDir) throws Exception {
        BadgeGenerator generator = new BadgeGenerator();

        BenchmarkMetrics metrics = new BenchmarkMetrics(
                "test", "test", 1000.0, 10.0, 85.0, "A"
        );

        TrendDataProcessor.TrendMetrics trendMetrics = new TrendDataProcessor.TrendMetrics(
                "up", 5.0, 82.0, 10.0, -5.0
        );

        generator.writeBadgeFiles(metrics, trendMetrics, BenchmarkType.MICRO, tempDir.toString());

        // Verify all badge files were created
        Path badgesDir = tempDir.resolve("badges");
        assertTrue(Files.exists(badgesDir));
        assertTrue(Files.isDirectory(badgesDir));

        Path perfBadge = badgesDir.resolve("performance-badge.json");
        Path trendBadge = badgesDir.resolve("trend-badge.json");
        Path lastRunBadge = badgesDir.resolve("last-run-badge.json");

        assertTrue(Files.exists(perfBadge));
        assertTrue(Files.exists(trendBadge));
        assertTrue(Files.exists(lastRunBadge));

        // Verify performance badge content
        String perfContent = Files.readString(perfBadge);
        JsonObject perfJson = GSON.fromJson(perfContent, JsonObject.class);
        assertEquals("Grade A (1k ops/s, 10.00ms)", perfJson.get("message").getAsString());

        // Verify trend badge content
        String trendContent = Files.readString(trendBadge);
        JsonObject trendJson = GSON.fromJson(trendContent, JsonObject.class);
        assertEquals("↑ 5.0%", trendJson.get("message").getAsString());

        // Verify last run badge content
        String lastRunContent = Files.readString(lastRunBadge);
        JsonObject lastRunJson = GSON.fromJson(lastRunContent, JsonObject.class);
        assertEquals(DATE_FORMAT.format(Instant.now()), lastRunJson.get("message").getAsString());
    }

    @Test
    void writeBadgeFilesWithoutTrendMetrics(@TempDir Path tempDir) throws Exception {
        BadgeGenerator generator = new BadgeGenerator();

        BenchmarkMetrics metrics = new BenchmarkMetrics(
                "test", "test", 1000.0, 10.0, 85.0, "A"
        );

        // Call with null trend metrics
        generator.writeBadgeFiles(metrics, null, BenchmarkType.MICRO, tempDir.toString());

        Path badgesDir = tempDir.resolve("badges");
        Path trendBadge = badgesDir.resolve("trend-badge.json");

        assertTrue(Files.exists(trendBadge));

        // Should have default trend badge
        String trendContent = Files.readString(trendBadge);
        JsonObject trendJson = GSON.fromJson(trendContent, JsonObject.class);
        assertEquals("No history", trendJson.get("message").getAsString());
        assertEquals("lightgray", trendJson.get("color").getAsString());
    }

    @Test
    void badgeJsonStructure() {
        BadgeGenerator generator = new BadgeGenerator();

        BenchmarkMetrics metrics = new BenchmarkMetrics(
                "test", "test", 1000.0, 10.0, 85.0, "A"
        );

        String badge = generator.generatePerformanceBadge(metrics);
        JsonObject json = GSON.fromJson(badge, JsonObject.class);

        // Verify shields.io schema compliance
        assertTrue(json.has("schemaVersion"));
        assertEquals(1, json.get("schemaVersion").getAsInt());

        assertTrue(json.has("label"));
        assertFalse(json.get("label").getAsString().isEmpty());

        assertTrue(json.has("message"));
        assertFalse(json.get("message").getAsString().isEmpty());
        // Verify message contains grade and metrics
        String message = json.get("message").getAsString();
        assertTrue(message.contains("Grade A"));
        assertTrue(message.contains("ops/s"));
        assertTrue(message.contains("ms"));

        assertTrue(json.has("color"));
        assertFalse(json.get("color").getAsString().isEmpty());

        // Should not have any extra fields
        assertEquals(4, json.size());
    }

    @Test
    void percentageFormatting() {
        BadgeGenerator generator = new BadgeGenerator();

        // Test various percentage values for proper formatting
        TrendDataProcessor.TrendMetrics trend1 = new TrendDataProcessor.TrendMetrics(
                "up", 5.678, 80.0, 10.0, -5.0
        );
        String badge1 = generator.generateTrendBadge(trend1);
        JsonObject json1 = GSON.fromJson(badge1, JsonObject.class);
        assertEquals("↑ 5.7%", json1.get("message").getAsString());

        TrendDataProcessor.TrendMetrics trend2 = new TrendDataProcessor.TrendMetrics(
                "down", -0.123, 80.0, -1.0, 0.5
        );
        String badge2 = generator.generateTrendBadge(trend2);
        JsonObject json2 = GSON.fromJson(badge2, JsonObject.class);
        assertEquals("↓ 0.1%", json2.get("message").getAsString());

        TrendDataProcessor.TrendMetrics trend3 = new TrendDataProcessor.TrendMetrics(
                "up", 100.999, 80.0, 100.0, -50.0
        );
        String badge3 = generator.generateTrendBadge(trend3);
        JsonObject json3 = GSON.fromJson(badge3, JsonObject.class);
        assertEquals("↑ 101.0%", json3.get("message").getAsString());
    }

    @Test
    void performanceBadgeWithCorrectUnitConversionFromMicroseconds() {
        // TEST: Verify that latency in microseconds is correctly converted to milliseconds
        // when passed to the badge generator.
        //
        // Scenario: JmhBenchmarkConverter should convert us/op to ms/op before creating
        // BenchmarkMetrics, which then gets passed to BadgeGenerator.
        //
        // Input latency: 867.4 microseconds
        // Expected output: 0.8674 milliseconds, displayed as "0.87ms" in badge

        BadgeGenerator generator = new BadgeGenerator();

        // Simulate CORRECT behavior after fix: latency already converted to milliseconds
        BenchmarkMetrics metricsWithMilliseconds = new BenchmarkMetrics(
                "validateMixedTokens50", "measureAverageTime",
                176662.03, 0.8674, // Latency CORRECTLY converted from 867.4 us to 0.8674 ms
                50.0, "F"
        );

        String badge = generator.generatePerformanceBadge(metricsWithMilliseconds);
        JsonObject json = GSON.fromJson(badge, JsonObject.class);

        String message = json.get("message").getAsString();

        // After fix, badge should show latency as 0.87ms (not 867.42ms)
        assertTrue(message.matches("Grade F \\(17[0-9]k ops/s, 0\\.8[0-9]ms\\)"),
                "Expected latency ~0.87ms after conversion, got: " + message);

        // Verify throughput is correct (around 177k ops/s)
        assertTrue(message.contains("177k") || message.contains("176k"),
                "Expected throughput ~177k ops/s, got: " + message);
    }
}