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
package de.cuioss.benchmarking.common;

/**
 * Test constants for benchmarking tests.
 */
public final class TestConstants {

    private TestConstants() {
        // utility class
    }

    /** Default throughput benchmark name for tests. */
    public static final String DEFAULT_THROUGHPUT_BENCHMARK = "measureThroughput";

    /** Default latency benchmark name for tests. */
    public static final String DEFAULT_LATENCY_BENCHMARK = "measureLatency";
}