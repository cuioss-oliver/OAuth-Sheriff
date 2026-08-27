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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link OutputDirectoryStructure}.
 */
class OutputDirectoryStructureTest {

    @Test
    void constructorShouldRejectNullParameter() {
        assertThrows(NullPointerException.class, () -> new OutputDirectoryStructure(null));
    }

    @Test
    void ensureDirectoriesShouldCreateDeploymentDirectories(@TempDir Path tempDir) throws Exception {
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);

        // Initially, deployment directories should not exist
        assertFalse(Files.exists(structure.getDeploymentDir()));
        assertFalse(Files.exists(structure.getDataDir()));
        assertFalse(Files.exists(structure.getBadgesDir()));
        assertFalse(Files.exists(structure.getApiDir()));

        // Ensure deployment directories
        structure.ensureDirectories();

        // Deployment directories should now exist
        assertTrue(Files.exists(structure.getDeploymentDir()));
        assertTrue(Files.isDirectory(structure.getDeploymentDir()));
        assertTrue(Files.exists(structure.getDataDir()));
        assertTrue(Files.isDirectory(structure.getDataDir()));
        assertTrue(Files.exists(structure.getBadgesDir()));
        assertTrue(Files.isDirectory(structure.getBadgesDir()));
        assertTrue(Files.exists(structure.getApiDir()));
        assertTrue(Files.isDirectory(structure.getApiDir()));
    }

    @Test
    void ensureDirectoriesShouldBeIdempotent(@TempDir Path tempDir) throws Exception {
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);

        // Create directories first time
        structure.ensureDirectories();

        // Create some test files to ensure they're preserved
        Path testFile1 = structure.getDataDir().resolve("test1.json");
        Path testFile2 = structure.getBadgesDir().resolve("test2.json");
        Files.writeString(testFile1, "test content 1");
        Files.writeString(testFile2, "test content 2");

        // Call ensureDirectories again - should not fail
        assertDoesNotThrow(structure::ensureDirectories);

        // Verify files are still there
        assertTrue(Files.exists(testFile1));
        assertTrue(Files.exists(testFile2));
        assertEquals("test content 1", Files.readString(testFile1));
        assertEquals("test content 2", Files.readString(testFile2));
    }

    @Test
    void toStringShouldContainAllPaths(@TempDir Path tempDir) {
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);

        String toString = structure.toString();

        assertTrue(toString.contains("benchmarkResultsDir=" + benchmarkResultsDir));
        assertTrue(toString.contains("deploymentDir=" + benchmarkResultsDir.resolve("gh-pages-ready")));
        assertTrue(toString.contains("dataDir=" + benchmarkResultsDir.resolve("gh-pages-ready/data")));
        assertTrue(toString.contains("badgesDir=" + benchmarkResultsDir.resolve("gh-pages-ready/badges")));
        assertTrue(toString.contains("apiDir=" + benchmarkResultsDir.resolve("gh-pages-ready/api")));
        assertTrue(toString.contains("historyDir=" + benchmarkResultsDir.resolve("history")));
        assertTrue(toString.contains("prometheusRawDir=" + benchmarkResultsDir.resolve("prometheus")));
        assertTrue(toString.contains("wrkDir=" + benchmarkResultsDir.resolve("wrk")));
    }

}