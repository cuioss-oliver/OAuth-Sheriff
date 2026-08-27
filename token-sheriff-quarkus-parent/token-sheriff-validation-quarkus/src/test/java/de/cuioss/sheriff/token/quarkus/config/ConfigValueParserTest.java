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
package de.cuioss.sheriff.token.quarkus.config;

import de.cuioss.sheriff.token.quarkus.test.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("ConfigValueParser")
class ConfigValueParserTest {

    @Nested
    @DisplayName("splitCsv")
    class SplitCsv {

        @Test
        @DisplayName("should split and trim comma-separated values")
        void shouldSplitAndTrim() {
            assertEquals(List.of("a", "b", "c"), ConfigValueParser.splitCsv("a, b ,c"));
        }

        @Test
        @DisplayName("should filter empty segments consistently")
        void shouldFilterEmptySegments() {
            assertEquals(List.of("a", "b"), ConfigValueParser.splitCsv("a,,b"));
            assertEquals(List.of("a", "b"), ConfigValueParser.splitCsv(",a, ,b,"));
            assertEquals(List.of(), ConfigValueParser.splitCsv(""));
            assertEquals(List.of(), ConfigValueParser.splitCsv(" , ,"));
        }

        @Test
        @DisplayName("should handle single value without separator")
        void shouldHandleSingleValue() {
            assertEquals(List.of("only"), ConfigValueParser.splitCsv(" only "));
        }
    }

    @Nested
    @DisplayName("discoverNameSegments")
    class DiscoverNameSegments {

        @Test
        @DisplayName("should discover name segments after prefix")
        void shouldDiscoverNameSegments() {
            TestConfig config = new TestConfig(Map.of(
                    "sheriff.token.issuers.default.enabled", "true",
                    "sheriff.token.issuers.default.issuer-identifier", "https://example.com",
                    "sheriff.token.issuers.keycloak.enabled", "false",
                    "sheriff.token.other.property", "value"
            ));

            Set<String> names = ConfigValueParser.discoverNameSegments(config, "sheriff.token.issuers.");

            assertEquals(Set.of("default", "keycloak"), names);
        }

        @Test
        @DisplayName("should ignore properties without a dot after the prefix")
        void shouldIgnorePropertiesWithoutDot() {
            TestConfig config = new TestConfig(Map.of(
                    "prefix.name.sub", "value",
                    "prefix.plain", "value"
            ));

            Set<String> names = ConfigValueParser.discoverNameSegments(config, "prefix.");

            assertEquals(Set.of("name"), names);
        }

        @Test
        @DisplayName("should return empty set when no properties match")
        void shouldReturnEmptySetWhenNoMatch() {
            TestConfig config = new TestConfig(Map.of("unrelated.property", "value"));

            assertTrue(ConfigValueParser.discoverNameSegments(config, "prefix.").isEmpty());
        }
    }
}
