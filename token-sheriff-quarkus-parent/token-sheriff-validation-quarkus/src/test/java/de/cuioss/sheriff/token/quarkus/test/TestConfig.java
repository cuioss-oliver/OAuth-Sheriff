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
package de.cuioss.sheriff.token.quarkus.test;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigValue;
import org.eclipse.microprofile.config.spi.ConfigSource;
import org.eclipse.microprofile.config.spi.Converter;

import java.util.*;

/**
 * Simple test implementation of {@link Config} for unit testing purposes.
 * This class provides a minimal implementation of the MicroProfile Config interface
 * that can be used in unit tests without requiring a full CDI container.
 * 
 * <p>Usage example:</p>
 * <pre>
 * Map&lt;String, String&gt; props = Map.of(
 *     "app.name", "test-app",
 *     "app.version", "1.0.0"
 * );
 * Config config = new TestConfig(props);
 * </pre>
 */
public class TestConfig implements Config {

    private final Map<String, String> properties;

    /**
     * Creates a new TestConfig with the given properties.
     *
     * @param properties the configuration properties
     */
    public TestConfig(Map<String, String> properties) {
        this.properties = new HashMap<>(properties);
    }

    @Override
    public <T> T getValue(String propertyName, Class<T> propertyType) {
        String value = properties.get(propertyName);
        if (value == null) {
            throw new NoSuchElementException("Property " + propertyName + " not found");
        }
        return convertValue(value, propertyType);
    }

    @Override
    public <T> Optional<T> getOptionalValue(String propertyName, Class<T> propertyType) {
        String value = properties.get(propertyName);
        if (value == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(convertValue(value, propertyType));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    @Override
    public Iterable<String> getPropertyNames() {
        return properties.keySet();
    }

    @Override
    public Iterable<ConfigSource> getConfigSources() {
        return List.of();
    }

    @Override
    public <T> T unwrap(Class<T> type) {
        throw new IllegalArgumentException("Unwrapping not supported in test config");
    }

    @Override
    public <T> Optional<Converter<T>> getConverter(Class<T> forType) {
        return Optional.empty();
    }

    @Override
    public ConfigValue getConfigValue(String propertyName) {
        throw new IllegalArgumentException("ConfigValue not supported in test config");
    }

    @SuppressWarnings("unchecked")
    private <T> T convertValue(String value, Class<T> targetType) {
        if (targetType == String.class) {
            return (T) value;
        } else if (targetType == Integer.class || targetType == int.class) {
            return (T) Integer.valueOf(value);
        } else if (targetType == Boolean.class || targetType == boolean.class) {
            return (T) Boolean.valueOf(value);
        } else if (targetType == Long.class || targetType == long.class) {
            return (T) Long.valueOf(value);
        } else if (targetType == Double.class || targetType == double.class) {
            return (T) Double.valueOf(value);
        }
        throw new IllegalArgumentException("Unsupported type: " + targetType);
    }
}