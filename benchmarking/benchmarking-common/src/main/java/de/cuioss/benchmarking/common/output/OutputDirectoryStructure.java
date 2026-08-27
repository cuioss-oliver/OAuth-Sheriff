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
package de.cuioss.benchmarking.common.output;

import lombok.Getter;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Objects;

/**
 * Manages the output directory structure for benchmark results.
 * Provides clear separation between deployable content (gh-pages-ready)
 * and non-deployable raw data (history, prometheus, wrk).
 * <p>
 * Directory structure:
 * <pre>
 * benchmark-results/
 * ├── gh-pages-ready/         (deploymentDir, htmlDir) - All content deployable to GitHub Pages
 * │   ├── data/               (dataDir) - JSON data files
 * │   ├── badges/             (badgesDir) - Badge JSON files
 * │   └── api/                (apiDir) - API endpoint JSON files
 * ├── history/                (historyDir) - Historical archive data (NOT deployed)
 * ├── prometheus/             (prometheusRawDir) - Raw Prometheus metrics (NOT deployed)
 * └── wrk/                    (wrkDir) - WRK raw results (NOT deployed)
 * </pre>
 */
public class OutputDirectoryStructure {

    /** Root benchmark-results directory */
    @Getter
    private final Path benchmarkResultsDir;

    /**
     * Deployment directory (gh-pages-ready) - all content in this directory
     * is deployable to GitHub Pages
     */
    @Getter
    private final Path deploymentDir;

    /**
     * HTML directory (same as deployment directory) - HTML files should be
     * written directly to this directory
     */
    @Getter
    private final Path htmlDir;

    /** Data directory (gh-pages-ready/data) - JSON data files location */
    @Getter
    private final Path dataDir;

    /** Badges directory (gh-pages-ready/badges) - Badge JSON files location */
    @Getter
    private final Path badgesDir;

    /** API directory (gh-pages-ready/api) - API endpoint JSON files location */
    @Getter
    private final Path apiDir;

    // Non-deployed directories (in benchmark-results root)
    private final Path historyDir;           // benchmark-results/history
    private final Path prometheusRawDir;     // benchmark-results/prometheus
    private final Path wrkDir;               // benchmark-results/wrk (WRK module only)

    /**
     * Creates a new output directory structure.
     *
     * @param benchmarkResultsDir the root benchmark-results directory
     * @throws NullPointerException if benchmarkResultsDir is null
     */
    public OutputDirectoryStructure(Path benchmarkResultsDir) {
        this.benchmarkResultsDir = Objects.requireNonNull(benchmarkResultsDir,
                "benchmarkResultsDir must not be null");
        this.deploymentDir = benchmarkResultsDir.resolve("gh-pages-ready");
        this.htmlDir = deploymentDir;
        this.dataDir = deploymentDir.resolve("data");
        this.badgesDir = deploymentDir.resolve("badges");
        this.apiDir = deploymentDir.resolve("api");

        // Non-deployed directories stay in root
        this.historyDir = benchmarkResultsDir.resolve("history");
        this.prometheusRawDir = benchmarkResultsDir.resolve("prometheus");
        this.wrkDir = benchmarkResultsDir.resolve("wrk");
    }

    /**
     * Ensures deployment directories exist, creating them if necessary.
     * Non-deployed directories (history, prometheus, wrk) are created only when accessed.
     *
     * @throws IOException if directory creation fails
     */
    public void ensureDirectories() throws IOException {
        // Create deployment directories (always needed)
        Files.createDirectories(deploymentDir);
        Files.createDirectories(dataDir);
        Files.createDirectories(badgesDir);
        Files.createDirectories(apiDir);

        // Non-deployed directories are created on-demand by individual getters
        // to avoid creating unused directories in modules that don't need them
    }

    /**
     * Gets the raw Prometheus metrics directory (benchmark-results/prometheus).
     * Raw Prometheus data should be stored in this directory.
     * This directory is NOT deployed to GitHub Pages.
     * Creates the directory if it doesn't exist.
     *
     * @return the raw Prometheus directory path
     * @throws IOException if directory creation fails
     */
    public Path getPrometheusRawDir() throws IOException {
        Files.createDirectories(prometheusRawDir);
        return prometheusRawDir;
    }

    /**
     * Recursively deletes a directory and all its contents.
     *
     * @param path the directory to delete
     * @throws IOException if deletion fails
     */
    private void deleteDirectoryRecursively(Path path) throws IOException {
        if (Files.exists(path)) {
            try (var stream = Files.walk(path)) {
                stream.sorted(Comparator.reverseOrder())
                        .forEach(p -> {
                            try {
                                Files.delete(p);
                            } catch (IOException e) {
                                throw new UncheckedIOException("Failed to delete: " + p, e);
                            }
                        });
            }
        }
    }

    @Override
    public String toString() {
        return "OutputDirectoryStructure{" +
                "benchmarkResultsDir=" + benchmarkResultsDir +
                ", deploymentDir=" + deploymentDir +
                ", dataDir=" + dataDir +
                ", badgesDir=" + badgesDir +
                ", apiDir=" + apiDir +
                ", historyDir=" + historyDir +
                ", prometheusRawDir=" + prometheusRawDir +
                ", wrkDir=" + wrkDir +
                '}';
    }
}