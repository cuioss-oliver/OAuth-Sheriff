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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for HistoricalDataManager.
 */
class HistoricalDataManagerTest {

    @Test
    void hasHistoricalData(@TempDir Path tempDir) throws Exception {
        HistoricalDataManager manager = new HistoricalDataManager();

        // Test with no history directory
        assertFalse(manager.hasHistoricalData(tempDir.toString()));

        // Create history directory but empty
        Path historyDir = tempDir.resolve("history");
        Files.createDirectories(historyDir);
        assertFalse(manager.hasHistoricalData(tempDir.toString()));

        // Add a JSON file
        Files.writeString(historyDir.resolve("test.json"), "{}");
        assertTrue(manager.hasHistoricalData(tempDir.toString()));
    }


    @Test
    void archiveCurrentRun(@TempDir Path tempDir) throws Exception {
        HistoricalDataManager manager = new HistoricalDataManager();
        Map<String, Object> data = new HashMap<>();
        data.put("overview", Map.of("throughput", "1.5K ops/s"));

        manager.archiveCurrentRun(data, tempDir.toString(), "abcdef1234567890");

        Path historyDir = tempDir.resolve("history");
        try (var files = Files.list(historyDir)) {
            List<Path> archived = files.toList();
            assertEquals(1, archived.size());
            String name = archived.getFirst().getFileName().toString();
            assertTrue(name.endsWith("-abcdef12.json"), "filename carries truncated sha: " + name);
            assertTrue(Files.readString(archived.getFirst()).contains("1.5K ops/s"));
        }
    }

    @Test
    void archiveWithNullCommitSha(@TempDir Path tempDir) throws Exception {
        HistoricalDataManager manager = new HistoricalDataManager();
        manager.archiveCurrentRun(new HashMap<>(), tempDir.toString(), null);

        try (var files = Files.list(tempDir.resolve("history"))) {
            List<Path> archived = files.toList();
            assertEquals(1, archived.size());
            assertTrue(archived.getFirst().getFileName().toString().endsWith("-unknown.json"));
        }
    }

    @Test
    void enforceRetentionPolicy(@TempDir Path tempDir) throws Exception {
        HistoricalDataManager manager = new HistoricalDataManager();
        Path historyDir = tempDir.resolve("history");
        Files.createDirectories(historyDir);
        for (int i = 10; i < 25; i++) {
            Files.writeString(historyDir.resolve("2025-01-" + i + "-T0000Z-sha" + i + ".json"), "{}");
        }

        manager.enforceRetentionPolicy(historyDir);

        try (var files = Files.list(historyDir)) {
            assertEquals(HistoricalDataManager.HISTORY_LIMIT, files.count(),
                    "retention keeps only the newest HISTORY_LIMIT files");
        }
        // newest files survive
        assertTrue(Files.exists(historyDir.resolve("2025-01-24-T0000Z-sha24.json")));
        assertFalse(Files.exists(historyDir.resolve("2025-01-10-T0000Z-sha10.json")));
    }

    @Test
    void resolveHistoryDirDefaultsToOutputSubdirectory(@TempDir Path tempDir) {
        assertEquals(tempDir.resolve("history"),
                HistoricalDataManager.resolveHistoryDir(tempDir.toString()));
    }

    @Test
    void filenameHelpersParseTimestampAndSha() {
        assertEquals("2025-01-24-T0000Z", HistoricalDataManager.timestampFromFilename("2025-01-24-T0000Z-abcd1234.json"));
        assertEquals("abcd1234", HistoricalDataManager.commitFromFilename("2025-01-24-T0000Z-abcd1234.json"));
        assertEquals("unknown", HistoricalDataManager.commitFromFilename("nodashname"));
    }
}
