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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import static de.cuioss.benchmarking.common.TestHelper.createTestMetrics;
import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Report.Badge.*;
import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Report.Badge.Colors.BLUE;
import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Report.Badge.Labels.LAST_RUN;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for BadgeGenerator using real JSON test data.
 */
class BadgeGeneratorTest {

    private final Gson gson = new Gson();

    @Test
    void integrationBadgeGeneration(@TempDir Path tempDir) throws Exception {
        // Use real integration benchmark JSON
        Path jsonFile = Path.of("src/test/resources/integration-benchmark-results/integration-result.json");
        assertTrue(Files.exists(jsonFile));

        // Generate badge
        BadgeGenerator generator = new BadgeGenerator();
        String badgeJson = generator.generatePerformanceBadge(createTestMetrics(jsonFile));
        Path badgeFile = tempDir.resolve(FileNames.INTEGRATION_PERFORMANCE_BADGE_JSON);
        Files.writeString(badgeFile, badgeJson);

        // Verify badge file was created
        assertTrue(Files.exists(badgeFile));

        // Read and verify badge content
        String badgeContent = Files.readString(badgeFile);
        JsonObject badge = gson.fromJson(badgeContent, JsonObject.class);

        // Verify structure
        assertEquals(1, badge.get(SCHEMA_VERSION).getAsInt());
        assertEquals("Performance", badge.get(LABEL).getAsString());
        assertNotNull(badge.get(MESSAGE).getAsString());
        assertNotNull(badge.get(COLOR).getAsString());

        // Verify message format: "Grade X"
        String message = badge.get(MESSAGE).getAsString();
        assertNotNull(message, "Badge message must exist");
        assertFalse(message.isEmpty(), "Badge message must not be empty");

        // Parse the message to verify it contains a grade
        // Expected format: "Grade A", "Grade B", etc.
        assertTrue(message.startsWith("Grade "),
                "Message should start with 'Grade '");
    }

    @Test
    void microBadgeGeneration(@TempDir Path tempDir) throws Exception {
        // Use real micro benchmark JSON
        Path jsonFile = Path.of("src/test/resources/library-benchmark-results/micro-result.json");
        assertTrue(Files.exists(jsonFile));

        // Generate badge
        BadgeGenerator generator = new BadgeGenerator();
        String badgeJson = generator.generatePerformanceBadge(createTestMetrics(jsonFile));
        Path badgeFile = tempDir.resolve(FileNames.PERFORMANCE_BADGE_JSON);
        Files.writeString(badgeFile, badgeJson);

        // Verify badge file was created
        assertTrue(Files.exists(badgeFile));

        // Read and verify badge content
        String badgeContent = Files.readString(badgeFile);
        JsonObject badge = gson.fromJson(badgeContent, JsonObject.class);

        // Verify structure
        assertEquals(1, badge.get(SCHEMA_VERSION).getAsInt());
        assertEquals("Performance", badge.get(LABEL).getAsString());
        assertNotNull(badge.get(MESSAGE).getAsString());
        assertNotNull(badge.get(COLOR).getAsString());

        // Verify message contains expected format
        String message = badge.get(MESSAGE).getAsString();
        assertNotNull(message, "Badge message must exist");
        assertFalse(message.isEmpty(), "Badge message must not be empty");

        // Verify it contains a grade
        assertTrue(message.startsWith("Grade "),
                "Message should start with 'Grade '");
    }

    @Test
    void trendBadgeGeneration(@TempDir Path tempDir) throws Exception {
        Path jsonFile = Path.of("src/test/resources/integration-benchmark-results/integration-result.json");
        assertTrue(Files.exists(jsonFile));

        BadgeGenerator generator = new BadgeGenerator();
        // Generate default trend badge (no history)
        String badgeJson = generator.generateDefaultTrendBadge();
        Path badgeFile = tempDir.resolve(FileNames.INTEGRATION_TREND_BADGE_JSON);
        Files.writeString(badgeFile, badgeJson);
        assertTrue(Files.exists(badgeFile));

        String badgeContent = Files.readString(badgeFile);
        JsonObject badge = gson.fromJson(badgeContent, JsonObject.class);

        assertEquals(1, badge.get(SCHEMA_VERSION).getAsInt());
        assertEquals("Trend", badge.get(LABEL).getAsString());
        assertEquals("No history", badge.get(MESSAGE).getAsString());
        assertEquals("lightgray", badge.get(COLOR).getAsString());
    }

    @Test
    void lastRunBadgeGeneration(@TempDir Path tempDir) throws Exception {
        BadgeGenerator generator = new BadgeGenerator();
        String badgeJson = generator.generateLastRunBadge(Instant.now());
        Path badgeFile = tempDir.resolve(FileNames.LAST_RUN_BADGE_JSON);
        Files.writeString(badgeFile, badgeJson);
        assertTrue(Files.exists(badgeFile));

        String badgeContent = Files.readString(badgeFile);
        JsonObject badge = gson.fromJson(badgeContent, JsonObject.class);

        assertEquals(1, badge.get(SCHEMA_VERSION).getAsInt());
        assertEquals(LAST_RUN, badge.get(LABEL).getAsString());
        assertNotNull(badge.get(MESSAGE).getAsString());
        assertEquals(BLUE, badge.get(COLOR).getAsString());
    }
}