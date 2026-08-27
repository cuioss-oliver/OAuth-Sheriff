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

import de.cuioss.benchmarking.common.output.OutputDirectoryStructure;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link GitHubPagesGenerator}.
 */
class GitHubPagesGeneratorTest {

    @Test
    void generateDeploymentAssetsShouldCreateAllRequiredFiles(@TempDir Path tempDir) throws Exception {
        // Arrange
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);
        GitHubPagesGenerator generator = new GitHubPagesGenerator();

        // Act
        generator.generateDeploymentAssets(structure);

        // Assert - verify deployment-specific files are created
        Path deployDir = structure.getDeploymentDir();
        assertTrue(Files.exists(deployDir.resolve("404.html")), "404.html should be created");
        assertTrue(Files.exists(deployDir.resolve("robots.txt")), "robots.txt should be created");
        assertTrue(Files.exists(deployDir.resolve("sitemap.xml")), "sitemap.xml should be created");

        // Verify content is not empty
        assertFalse(Files.readString(deployDir.resolve("404.html")).isEmpty(), "404.html should have content");
        assertFalse(Files.readString(deployDir.resolve("robots.txt")).isEmpty(), "robots.txt should have content");
        assertFalse(Files.readString(deployDir.resolve("sitemap.xml")).isEmpty(), "sitemap.xml should have content");
    }

    @Test
    void generateDeploymentAssetsShould404PageContainErrorMessage(@TempDir Path tempDir) throws Exception {
        // Arrange
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);
        GitHubPagesGenerator generator = new GitHubPagesGenerator();

        // Act
        generator.generateDeploymentAssets(structure);

        // Assert - verify 404 page contains expected content
        String content404 = Files.readString(structure.getDeploymentDir().resolve("404.html"));
        assertTrue(content404.contains("404"), "404 page should contain '404' text");
        assertTrue(content404.contains("Page Not Found") || content404.contains("not found"),
                "404 page should contain 'not found' message");
    }

    @Test
    void generateDeploymentAssetsShouldCreateDirectories(@TempDir Path tempDir) throws Exception {
        // Arrange
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);
        GitHubPagesGenerator generator = new GitHubPagesGenerator();

        // Initially directories should not exist
        assertFalse(Files.exists(structure.getDeploymentDir()));

        // Act
        generator.generateDeploymentAssets(structure);

        // Assert - verify directories are created
        assertTrue(Files.exists(structure.getDeploymentDir()), "Deployment directory should be created");
        assertTrue(Files.exists(structure.getDataDir()), "Data directory should be created");
        assertTrue(Files.exists(structure.getBadgesDir()), "Badges directory should be created");
        assertTrue(Files.exists(structure.getApiDir()), "API directory should be created");
    }

    @Test
    void generateDeploymentAssetsShouldBeIdempotent(@TempDir Path tempDir) throws Exception {
        // Arrange
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);
        GitHubPagesGenerator generator = new GitHubPagesGenerator();

        // Act - run twice
        generator.generateDeploymentAssets(structure);
        generator.generateDeploymentAssets(structure);

        // Assert - files should still exist and not throw exceptions
        Path deployDir = structure.getDeploymentDir();
        assertTrue(Files.exists(deployDir.resolve("404.html")));
        assertTrue(Files.exists(deployDir.resolve("robots.txt")));
        assertTrue(Files.exists(deployDir.resolve("sitemap.xml")));
    }


    @Test
    void robotsTxtShouldContainBasicDirectives(@TempDir Path tempDir) throws Exception {
        // Arrange
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);
        GitHubPagesGenerator generator = new GitHubPagesGenerator();

        // Act
        generator.generateDeploymentAssets(structure);

        // Assert
        String robotsContent = Files.readString(structure.getDeploymentDir().resolve("robots.txt"));
        assertTrue(robotsContent.contains("User-agent:") || robotsContent.contains("User-Agent:"),
                "robots.txt should contain User-agent directive");
    }

    @Test
    void sitemapXmlShouldBeValidXml(@TempDir Path tempDir) throws Exception {
        // Arrange
        Path benchmarkResultsDir = tempDir.resolve("benchmark-results");
        OutputDirectoryStructure structure = new OutputDirectoryStructure(benchmarkResultsDir);
        GitHubPagesGenerator generator = new GitHubPagesGenerator();

        // Act
        generator.generateDeploymentAssets(structure);

        // Assert - verify sitemap is XML
        String sitemapContent = Files.readString(structure.getDeploymentDir().resolve("sitemap.xml"));
        assertTrue(sitemapContent.contains("<?xml"), "sitemap.xml should start with XML declaration");
        assertTrue(sitemapContent.contains("<urlset") || sitemapContent.contains("<sitemapindex"),
                "sitemap.xml should contain urlset or sitemapindex element");
    }
}