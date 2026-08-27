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
package de.cuioss.benchmarking.common.config;

import lombok.Getter;

import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Report.Badge.FileNames;

/**
 * Enumeration of benchmark types supported by the CUI benchmarking infrastructure.
 * <p>
 * Each type has different characteristics and requirements for badge generation,
 * metrics collection, and reporting.
 */
@Getter
public enum BenchmarkType {
    /**
     * Micro benchmarks that test individual components or methods in isolation.
     * <p>
     * Characteristics:
     * <ul>
     *   <li>Fast execution (seconds to minutes)</li>
     *   <li>High precision measurements</li>
     *   <li>Minimal external dependencies</li>
     *   <li>Focus on throughput and latency</li>
     * </ul>
     */
    MICRO("micro", "Performance Score", "Micro Performance"),

    /**
     * Integration benchmarks that test complete workflows or external services.
     * <p>
     * Characteristics:
     * <ul>
     *   <li>Longer execution time (minutes to hours)</li>
     *   <li>Network and I/O overhead</li>
     *   <li>External service dependencies</li>
     *   <li>Focus on end-to-end performance</li>
     * </ul>
     */
    INTEGRATION("integration", "Integration Performance", "Integration Performance");

    private final String identifier;
    private final String badgeLabel;
    private final String displayName;

    BenchmarkType(String identifier, String badgeLabel, String displayName) {
        this.identifier = identifier;
        this.badgeLabel = badgeLabel;
        this.displayName = displayName;
    }

    /**
     * Gets the badge file name for performance badges.
     *
     * @return the performance badge file name
     */
    public String getPerformanceBadgeFileName() {
        return this == MICRO ? FileNames.PERFORMANCE_BADGE_JSON : FileNames.INTEGRATION_PERFORMANCE_BADGE_JSON;
    }

    /**
     * Gets the badge file name for trend badges.
     *
     * @return the trend badge file name
     */
    public String getTrendBadgeFileName() {
        return this == MICRO ? FileNames.TREND_BADGE_JSON : FileNames.INTEGRATION_TREND_BADGE_JSON;
    }
}