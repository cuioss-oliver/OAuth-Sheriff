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
package de.cuioss.benchmarking.common.metrics;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;
import de.cuioss.tools.logging.CuiLogger;

import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static de.cuioss.benchmarking.common.util.BenchmarkingLogMessages.WARN.*;

/**
 * Exports metrics data to JSON files in a target directory.
 * Handles JSON serialization, file writing, and metrics aggregation.
 *
 */
public class MetricsJsonExporter {

    private static final CuiLogger LOGGER = new CuiLogger(MetricsJsonExporter.class);

    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .serializeNulls()
            .registerTypeAdapter(Instant.class, (JsonSerializer<Instant>)
                    (src, typeOfSrc, context) -> new JsonPrimitive(src.toString()))
            .registerTypeAdapter(Number.class, (JsonSerializer<Number>) (src, typeOfSrc, context) -> {
                if (src instanceof Double || src instanceof Float) {
                    double value = src.doubleValue();
                    if (value == Math.floor(value) && !Double.isInfinite(value)) {
                        return new JsonPrimitive(src.longValue());
                    }
                    return new JsonPrimitive(value);
                }
                return new JsonPrimitive(src);
            })
            .create();

    private final Path targetDirectory;

    /**
     * Creates a new metrics JSON exporter.
     *
     * @param targetDirectory Directory where JSON files will be written
     */
    public MetricsJsonExporter(Path targetDirectory) {
        this.targetDirectory = targetDirectory;
        try {
            Files.createDirectories(targetDirectory);
            LOGGER.debug("MetricsJsonExporter initialized with target directory: %s (exists: %s)",
                    targetDirectory.toAbsolutePath(), Files.exists(targetDirectory));
        } catch (IOException e) {
            LOGGER.warn(e, FAILED_CREATE_TARGET_DIR, targetDirectory);
        }
    }

    /**
     * Exports metrics data to a JSON file.
     *
     * @param fileName The name of the JSON file
     * @param metricsData The metrics data to export
     * @throws IOException if writing fails
     */
    public void exportToFile(String fileName, Map<String, Object> metricsData) throws IOException {
        Path outputFile = targetDirectory.resolve(fileName);

        try (FileWriter writer = new FileWriter(outputFile.toFile())) {
            GSON.toJson(metricsData, writer);
            writer.flush();
            LOGGER.debug("Exported metrics to: %s", outputFile.toAbsolutePath());
        }
    }

    /**
     * Updates an aggregated metrics file with new benchmark data.
     *
     * @param fileName The name of the aggregated metrics file
     * @param benchmarkName The name of the benchmark
     * @param benchmarkData The benchmark data to add/update
     * @throws IOException if writing fails
     */
    public void updateAggregatedMetrics(String fileName, String benchmarkName,
            Map<String, Object> benchmarkData) throws IOException {
        Map<String, Object> allMetrics = readExistingMetrics(fileName);
        allMetrics.put(benchmarkName, benchmarkData);

        exportToFile(fileName, allMetrics);
        LOGGER.debug("Updated %s with %s benchmarks", fileName, allMetrics.size());
    }

    /**
     * Reads existing metrics from a JSON file.
     *
     * @param fileName The name of the JSON file
     * @return The parsed metrics map, or empty map if file doesn't exist or is empty
     */
    public Map<String, Object> readExistingMetrics(String fileName) {
        Map<String, Object> existingMetrics = new LinkedHashMap<>();
        Path filePath = targetDirectory.resolve(fileName);

        if (Files.exists(filePath)) {
            try {
                String content = Files.readString(filePath);
                if (!content.trim().isEmpty()) {
                    Type mapType = new TypeToken<Map<String, Object>>(){
                    }.getType();
                    Map<String, Object> parsed = GSON.fromJson(content, mapType);
                    if (parsed != null) {
                        existingMetrics = parsed;
                    }
                }
            } catch (IOException | JsonSyntaxException e) {
                LOGGER.warn(FAILED_READ_METRICS_FILE, fileName, e.getMessage());
                preserveCorruptFile(filePath);
            }
        }

        return existingMetrics;
    }

    /**
     * Moves a corrupt metrics file aside instead of deleting it, so the data
     * remains available for later inspection.
     *
     * @param filePath the corrupt metrics file
     */
    private void preserveCorruptFile(Path filePath) {
        try {
            Path preserved = filePath.resolveSibling(filePath.getFileName() + ".corrupt-" + System.currentTimeMillis());
            Files.move(filePath, preserved);
            LOGGER.warn(CORRUPT_METRICS_FILE_PRESERVED, preserved);
        } catch (IOException moveException) {
            LOGGER.warn(moveException, FAILED_PRESERVE_CORRUPT_FILE, filePath);
        }
    }
}
