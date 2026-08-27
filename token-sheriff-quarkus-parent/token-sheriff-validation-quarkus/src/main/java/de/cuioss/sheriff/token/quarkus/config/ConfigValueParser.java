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

import lombok.experimental.UtilityClass;
import org.eclipse.microprofile.config.Config;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Shared parsing helpers for configuration values used by the resolver classes.
 * <p>
 * Centralizes the CSV splitting and prefix-based name discovery logic that was
 * previously duplicated across {@code IssuerConfigResolver},
 * {@code AccessLogFilterConfigResolver}, and {@code JweDecryptionConfigResolver},
 * ensuring consistent handling of whitespace and empty segments.
 * </p>
 *
 * @since 1.0
 */
@UtilityClass
public final class ConfigValueParser {

    /**
     * Splits a comma-separated configuration value into its segments.
     * <p>
     * Each segment is trimmed, and empty segments (e.g. from {@code "a,,b"} or
     * trailing commas) are filtered out.
     * </p>
     *
     * @param value the raw comma-separated configuration value
     * @return immutable list of trimmed, non-empty segments; empty list if no segments remain
     */
    public static List<String> splitCsv(String value) {
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    /**
     * Discovers the distinct name segments that directly follow a property prefix.
     * <p>
     * For every property name starting with {@code prefix}, the substring up to the
     * next dot is collected. Properties without a further dot after the prefix are
     * ignored. For example, with prefix {@code "sheriff.token.issuers."} the property
     * {@code "sheriff.token.issuers.default.enabled"} yields the segment {@code "default"}.
     * </p>
     *
     * @param config the configuration to scan
     * @param prefix the property name prefix, typically ending with a dot
     * @return set of discovered name segments in encounter order
     */
    public static Set<String> discoverNameSegments(Config config, String prefix) {
        Set<String> names = new LinkedHashSet<>();
        for (String propertyName : config.getPropertyNames()) {
            if (propertyName.startsWith(prefix)) {
                String remainder = propertyName.substring(prefix.length());
                int firstDot = remainder.indexOf('.');
                if (firstDot > 0) {
                    names.add(remainder.substring(0, firstDot));
                }
            }
        }
        return names;
    }
}
