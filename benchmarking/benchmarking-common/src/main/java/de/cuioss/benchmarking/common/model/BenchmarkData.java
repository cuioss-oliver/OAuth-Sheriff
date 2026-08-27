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
package de.cuioss.benchmarking.common.model;

import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

/**
 * Central benchmark data model that can be populated from various sources
 * (JMH, WRK, custom benchmarks) and used by the reporting infrastructure.
 */
@Data
@Builder
public class BenchmarkData {

    /**
     * Metadata about the benchmark run
     */
    @Data
    @Builder
    public static class Metadata {
        private String timestamp;
        private String displayTimestamp;
        private String benchmarkType;
        private String reportVersion;
        private String projectName;
    }

    /**
     * Overview metrics for quick summary
     */
    @Data
    @Builder
    public static class Overview {
        private String throughput;              // Formatted display value (e.g., "140,0K ops/s")
        private String latency;                 // Formatted display value (e.g., "952,0 us/op")
        private Double throughputOpsPerSec;     // Numeric value: operations per second
        private Double latencyMs;               // Numeric value: latency in milliseconds
        private String throughputBenchmarkName;
        private String latencyBenchmarkName;
        private int performanceScore;
        private String performanceGrade;
        private String performanceGradeClass;
    }

    /**
     * Individual benchmark result
     */
    @Data
    @Builder
    public static class Benchmark {
        private String name;
        private String fullName;
        private String mode; // thrpt, avgt, sample, etc.
        private String score;
        private String scoreUnit;
        private Double rawScore; // Numeric value for calculations
        private String throughput; // For thrpt mode
        private String latency; // For avgt/sample mode
        private Double error;
        private Double variabilityCoefficient;
        private Double confidenceLow;
        private Double confidenceHigh;
        private Map<String, Double> percentiles;
        private Map<String, Object> additionalData; // For custom metrics
    }

    private Metadata metadata;
    private Overview overview;
    private List<Benchmark> benchmarks;
    private Map<String, Object> chartData;
    private Map<String, Object> trends;
}