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

import java.io.IOException;
import java.nio.file.Path;

/**
 * Interface for converting benchmark-specific formats to the central BenchmarkData model.
 * Implementations should handle specific benchmark tools (JMH, WRK, etc.)
 */
public interface BenchmarkConverter {

    /**
     * Converts benchmark results from a specific format to BenchmarkData
     *
     * @param sourcePath Path to the source benchmark results
     * @return Converted BenchmarkData
     * @throws IOException if conversion fails
     */
    BenchmarkData convert(Path sourcePath) throws IOException;

}