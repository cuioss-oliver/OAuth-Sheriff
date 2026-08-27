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
package de.cuioss.benchmarking.common.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JsonSerializationHelperTest {

    @TempDir
    Path tempDir;

    @Test
    void gsonConfiguration() {
        // Test that GSON is properly configured
        assertNotNull(JsonSerializationHelper.GSON);

        // Test pretty printing
        Map<String, Object> data = new HashMap<>();
        data.put("key", "value");
        String json = JsonSerializationHelper.GSON.toJson(data);
        assertTrue(json.contains("\n")); // Pretty printing adds newlines

        // Test Double serialization
        Double wholeNumber = 42.0;
        String wholeJson = JsonSerializationHelper.GSON.toJson(wholeNumber);
        assertEquals("42", wholeJson);

        Double decimal = 42.5;
        String decimalJson = JsonSerializationHelper.GSON.toJson(decimal);
        assertEquals("42.5", decimalJson);

        // Test Instant serialization
        Instant now = Instant.parse("2025-01-15T10:30:00Z");
        String instantJson = JsonSerializationHelper.GSON.toJson(now);
        assertEquals("\"2025-01-15T10:30:00Z\"", instantJson);
    }

    @Test
    void nullHandling() {
        // Test null Double serialization
        Double nullDouble = null;
        String nullJson = JsonSerializationHelper.GSON.toJson(nullDouble);
        assertEquals("null", nullJson);

        // Test null Instant serialization
        Instant nullInstant = null;
        String nullInstantJson = JsonSerializationHelper.GSON.toJson(nullInstant);
        assertEquals("null", nullInstantJson);
    }

    // Test helper class
    static class TestObject {
        int id;
        String name;
        Double value;
        Double wholeValue;
        String timestampString;
        boolean active;
    }
}