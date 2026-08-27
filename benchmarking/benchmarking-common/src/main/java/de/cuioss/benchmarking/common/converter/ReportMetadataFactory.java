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
package de.cuioss.benchmarking.common.converter;

import de.cuioss.benchmarking.common.model.BenchmarkData;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Report.DateFormats;
import static de.cuioss.benchmarking.common.constants.BenchmarkConstants.Report.Versions;

/**
 * Shared factory for report metadata — single home for timestamp formatting and
 * report versioning used by all benchmark converters.
 */
final class ReportMetadataFactory {

    private static final DateTimeFormatter DISPLAY_FORMAT =
            DateTimeFormatter.ofPattern(DateFormats.DISPLAY_TIMESTAMP_PATTERN).withZone(ZoneOffset.UTC);

    private ReportMetadataFactory() {
    }

    static BenchmarkData.Metadata createMetadata(String benchmarkTypeDisplayName, String projectName) {
        Instant now = Instant.now();
        return BenchmarkData.Metadata.builder()
                .timestamp(now.toString())
                .displayTimestamp(DISPLAY_FORMAT.format(now))
                .benchmarkType(benchmarkTypeDisplayName)
                .reportVersion(Versions.REPORT_VERSION)
                .projectName(projectName)
                .build();
    }
}
