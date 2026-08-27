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

import de.cuioss.benchmarking.common.util.JsonSerializationHelper;
import de.cuioss.tools.logging.CuiLogger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.INFO;
import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.WARN;

/**
 * Manages historical benchmark data persistence.
 * <p>
 * This manager handles:
 * <ul>
 *   <li>Saving current benchmark runs to history with timestamp-based naming</li>
 *   <li>Maintaining a retention policy (keeping only the most recent runs)</li>
 *   <li>Organizing historical data in a queryable directory structure</li>
 * </ul>
 * <p>
 * File naming convention: {@code YYYY-MM-DD-THHMMZ-{commitSha}.json}
 * where the timestamp is in UTC and the commit SHA is truncated to 8 characters.
 */
public class HistoricalDataManager {

    private static final CuiLogger LOGGER = new CuiLogger(HistoricalDataManager.class);
    /**
     * Single limit for archived history: retention on write and load window for trends.
     */
    public static final int HISTORY_LIMIT = 10;
    private static final String HISTORY_DIR = "history";
    private static final String JSON_EXTENSION = ".json";
    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd-'T'HHmm'Z'").withZone(ZoneOffset.UTC);


    /**
     * Archives the current benchmark data to the history directory.
     *
     * @param currentData the current benchmark data to archive
     * @param outputDir the base output directory
     * @param commitSha the Git commit SHA (will be truncated to 8 chars)
     * @throws IOException if writing the archive file fails
     */
    public void archiveCurrentRun(Map<String, Object> currentData, String outputDir, String commitSha)
            throws IOException {
        Path historyDir = resolveHistoryDir(outputDir);
        Files.createDirectories(historyDir);

        String timestamp = TIMESTAMP_FORMAT.format(Instant.now());
        String truncatedSha = commitSha != null && commitSha.length() >= 8
                ? commitSha.substring(0, 8)
                : "unknown";
        String filename = "%s-%s%s".formatted(timestamp, truncatedSha, JSON_EXTENSION);

        Path archiveFile = historyDir.resolve(filename);
        String jsonContent = JsonSerializationHelper.toJson(currentData);
        Files.writeString(archiveFile, jsonContent);

        LOGGER.info(INFO.ARCHIVED_BENCHMARK_DATA, archiveFile);
    }

    /**
     * Enforces the retention policy by keeping only the most recent files.
     *
     * @param historyDir the history directory path
     * @throws IOException if accessing or deleting files fails
     */
    public void enforceRetentionPolicy(Path historyDir) throws IOException {
        if (!Files.exists(historyDir)) {
            return;
        }

        try (Stream<Path> files = Files.list(historyDir)) {
            List<Path> jsonFiles = files
                    .filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(JSON_EXTENSION))
                    .sorted(Comparator.comparing(this::extractTimestamp).reversed())
                    .toList();

            if (jsonFiles.size() > HISTORY_LIMIT) {
                List<Path> filesToDelete = jsonFiles.subList(HISTORY_LIMIT, jsonFiles.size());
                for (Path file : filesToDelete) {
                    Files.delete(file);
                    LOGGER.info(INFO.REMOVED_HISTORY_FILE, file.getFileName());
                }
            }
        }
    }

    /**
     * Checks if historical data is available.
     *
     * @param outputDir the base output directory
     * @return true if historical data exists, false otherwise
     */
    public boolean hasHistoricalData(String outputDir) {
        Path historyDir = Path.of(outputDir, HISTORY_DIR);
        if (!Files.exists(historyDir)) {
            return false;
        }

        try (Stream<Path> files = Files.list(historyDir)) {
            return files
                    .filter(Files::isRegularFile)
                    .anyMatch(p -> p.toString().endsWith(JSON_EXTENSION));
        } catch (IOException e) {
            LOGGER.warn(e, WARN.ISSUE_DURING_INDEX_GENERATION, "checking historical data");
            return false;
        }
    }

    /**
     * Resolves the single history directory used for archiving, retention and trend
     * analysis. Honors the {@code benchmark.history.dir} system property (CI/CD
     * workflows); defaults to {@code <outputDir>/history}.
     *
     * @param outputDir the base output directory
     * @return the resolved history directory
     */
    public static Path resolveHistoryDir(String outputDir) {
        String externalHistoryPath = System.getProperty("benchmark.history.dir");
        if (externalHistoryPath != null && !externalHistoryPath.isEmpty()) {
            return Path.of(externalHistoryPath);
        }
        return Path.of(outputDir, HISTORY_DIR);
    }

    /**
     * Extracts the timestamp prefix from a history filename ({@code <timestamp>-<sha>.json}).
     *
     * @param filename the history file name
     * @return the timestamp portion, or the filename itself if it has no dash
     */
    public static String timestampFromFilename(String filename) {
        int dashIndex = filename.lastIndexOf('-');
        if (dashIndex > 0) {
            return filename.substring(0, dashIndex);
        }
        return filename;
    }

    /**
     * Extracts the commit SHA portion from a history filename ({@code <timestamp>-<sha>.json}).
     *
     * @param filename the history file name
     * @return the SHA portion, or "unknown" if the pattern does not match
     */
    public static String commitFromFilename(String filename) {
        int dashIndex = filename.lastIndexOf('-');
        int dotIndex = filename.lastIndexOf('.');
        if (dashIndex > 0 && dotIndex > dashIndex) {
            return filename.substring(dashIndex + 1, dotIndex);
        }
        return "unknown";
    }

    /**
     * Extracts the timestamp from a historical data filename.
     *
     * @param file the file path
     * @return the timestamp string, or empty string if extraction fails
     */
    private String extractTimestamp(Path file) {
        return timestampFromFilename(file.getFileName().toString());
    }
}