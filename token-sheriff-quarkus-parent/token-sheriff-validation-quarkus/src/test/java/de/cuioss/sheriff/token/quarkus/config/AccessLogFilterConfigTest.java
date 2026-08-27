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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AccessLogFilterConfig Tests")
class AccessLogFilterConfigTest {

    @Test
    @DisplayName("Should validate default config without errors")
    void shouldValidateDefaultConfig() {
        // Given
        var config = AccessLogFilterConfig.builder().build();

        // When / Then
        assertDoesNotThrow(config::validate);
    }

    @Test
    @DisplayName("Should validate custom valid config")
    void shouldValidateCustomValidConfig() {
        // Given
        var config = AccessLogFilterConfig.builder()
                .minStatusCode(200)
                .maxStatusCode(499)
                .build();

        // When / Then
        assertDoesNotThrow(config::validate);
    }

    @Test
    @DisplayName("Should reject minStatusCode below 100")
    void shouldRejectMinStatusCodeBelow100() {
        // Given
        var config = AccessLogFilterConfig.builder()
                .minStatusCode(99)
                .build();

        // When / Then
        var exception = assertThrows(IllegalArgumentException.class, config::validate);
        assertTrue(exception.getMessage().contains("minStatusCode must be in [100, 599]"));
    }

    @Test
    @DisplayName("Should reject minStatusCode above 599")
    void shouldRejectMinStatusCodeAbove599() {
        // Given
        var config = AccessLogFilterConfig.builder()
                .minStatusCode(600)
                .build();

        // When / Then
        var exception = assertThrows(IllegalArgumentException.class, config::validate);
        assertTrue(exception.getMessage().contains("minStatusCode must be in [100, 599]"));
    }

    @Test
    @DisplayName("Should reject maxStatusCode below 100")
    void shouldRejectMaxStatusCodeBelow100() {
        // Given
        var config = AccessLogFilterConfig.builder()
                .minStatusCode(100)
                .maxStatusCode(99)
                .build();

        // When / Then
        var exception = assertThrows(IllegalArgumentException.class, config::validate);
        assertTrue(exception.getMessage().contains("maxStatusCode must be in [100, 599]"));
    }

    @Test
    @DisplayName("Should reject maxStatusCode above 599")
    void shouldRejectMaxStatusCodeAbove599() {
        // Given
        var config = AccessLogFilterConfig.builder()
                .maxStatusCode(600)
                .build();

        // When / Then
        var exception = assertThrows(IllegalArgumentException.class, config::validate);
        assertTrue(exception.getMessage().contains("maxStatusCode must be in [100, 599]"));
    }

    @Test
    @DisplayName("Should reject maxStatusCode less than minStatusCode")
    void shouldRejectMaxStatusCodeLessThanMin() {
        // Given
        var config = AccessLogFilterConfig.builder()
                .minStatusCode(500)
                .maxStatusCode(400)
                .build();

        // When / Then
        var exception = assertThrows(IllegalArgumentException.class, config::validate);
        assertTrue(exception.getMessage().contains("minStatusCode"));
        assertTrue(exception.getMessage().contains("must not exceed"));
        assertTrue(exception.getMessage().contains("maxStatusCode"));
    }

    @Test
    @DisplayName("Should accept boundary values 100 and 599")
    void shouldAcceptBoundaryValues() {
        // Given
        var config = AccessLogFilterConfig.builder()
                .minStatusCode(100)
                .maxStatusCode(599)
                .build();

        // When / Then
        assertDoesNotThrow(config::validate);
    }

    @Test
    @DisplayName("Should accept equal min and max status codes")
    void shouldAcceptEqualMinAndMax() {
        // Given
        var config = AccessLogFilterConfig.builder()
                .minStatusCode(400)
                .maxStatusCode(400)
                .build();

        // When / Then
        assertDoesNotThrow(config::validate);
    }
}
