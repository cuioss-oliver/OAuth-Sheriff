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

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Map;

/**
 * Common JSON serialization utilities for benchmark results.
 * Provides consistent formatting and serialization across all benchmark modules.
 *
 */
public final class JsonSerializationHelper {

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_INSTANT;

    /**
     * Gson instance configured for benchmark result serialization.
     * Features:
     * - Pretty printing
     * - Smart number formatting (integers without .0)
     * - ISO instant formatting
     * - Special floating point value serialization
     * - Thread-safe singleton
     */
    public static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .serializeSpecialFloatingPointValues()
            .registerTypeAdapter(Double.class, new DoubleSerializer())
            .registerTypeAdapter(Instant.class, new InstantSerializer())
            .create();

    private JsonSerializationHelper() {
        // Utility class
    }

    /**
     * Serializes an object to JSON string using the default GSON instance.
     *
     * @param object the object to serialize
     * @return the JSON string representation
     */
    public static String toJson(Object object) {
        return GSON.toJson(object);
    }

    /**
     * Deserializes a JSON string to an object.
     *
     * @param <T> the type to deserialize to
     * @param json the JSON string
     * @param type the class of the type to deserialize
     * @return the deserialized object
     */
    public static <T> T fromJson(String json, Class<T> type) {
        return GSON.fromJson(json, type);
    }

    /**
     * Deserializes a JSON string to a generic type using TypeToken.
     *
     * @param <T> the type to deserialize to
     * @param json the JSON string
     * @param typeToken the TypeToken representing the generic type
     * @return the deserialized object
     */
    public static <T> T fromJson(String json, TypeToken<T> typeToken) {
        return GSON.fromJson(json, typeToken.getType());
    }

    /**
     * Convenience method for deserializing JSON to Map&lt;String, Object&gt;.
     *
     * @param json the JSON string
     * @return the deserialized map
     */
    public static Map<String, Object> jsonToMap(String json) {
        Type type = new TypeToken<Map<String, Object>>() {
        }.getType();
        return GSON.fromJson(json, type);
    }

    /**
     * Custom serializer for Double values.
     * Serializes whole numbers without decimal point.
     */
    private static class DoubleSerializer implements JsonSerializer<Double> {
        @Override
        public JsonElement serialize(Double src, Type typeOfSrc, JsonSerializationContext context) {
            if (src == null) {
                return JsonNull.INSTANCE;
            }
            if (src.isNaN() || src.isInfinite()) {
                return new JsonPrimitive(src.toString());
            }
            if (src == src.longValue()) {
                return new JsonPrimitive(src.longValue());
            }
            return new JsonPrimitive(src);
        }
    }

    /**
     * Custom serializer for Instant values.
     * Serializes to ISO-8601 format.
     */
    private static class InstantSerializer implements JsonSerializer<Instant> {
        @Override
        public JsonElement serialize(Instant src, Type typeOfSrc, JsonSerializationContext context) {
            if (src == null) {
                return JsonNull.INSTANCE;
            }
            return new JsonPrimitive(ISO_FORMATTER.format(src));
        }
    }

}