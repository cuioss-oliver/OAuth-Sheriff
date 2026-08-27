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

import de.cuioss.tools.logging.CuiLogger;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.Config;

import java.util.List;
import java.util.Optional;

import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.INFO;

/**
 * Resolver for creating {@link AccessLogFilterConfig} instances from Quarkus configuration.
 * <p>
 * This resolver handles the creation of access log filter configuration from properties,
 * providing sensible defaults for all optional values.
 * </p>
 * <p>
 * Configuration properties are defined in {@link JwtPropertyKeys.ACCESSLOG}.
 * </p>
 * <p>
 * Control via enabled flag: cui.http.access-log.filter.enabled=true
 * - true: Enable access logging
 * - false: Disable access logging (default)
 * </p>
 *
 * @since 1.0
 */
@ApplicationScoped
public class AccessLogFilterConfigResolver {

    private static final CuiLogger LOGGER = new CuiLogger(AccessLogFilterConfigResolver.class);

    private final Config config;

    @Inject
    public AccessLogFilterConfigResolver(Config config) {
        this.config = config;
    }

    /**
     * Resolves the access log filter configuration from the Quarkus configuration.
     * <p>
     * Uses default values if properties are not configured.
     * </p>
     *
     * @return The resolved AccessLogFilterConfig
     */
    public AccessLogFilterConfig resolveConfig() {
        LOGGER.info(INFO.RESOLVING_ACCESS_LOG_FILTER_CONFIG);

        var builder = AccessLogFilterConfig.builder();
        config.getOptionalValue(JwtPropertyKeys.ACCESSLOG.MIN_STATUS_CODE, Integer.class)
                .ifPresent(builder::minStatusCode);
        config.getOptionalValue(JwtPropertyKeys.ACCESSLOG.MAX_STATUS_CODE, Integer.class)
                .ifPresent(builder::maxStatusCode);
        resolveIntegerList(JwtPropertyKeys.ACCESSLOG.INCLUDE_STATUS_CODES)
                .ifPresent(builder::includeStatusCodes);
        resolveStringList(JwtPropertyKeys.ACCESSLOG.INCLUDE_PATHS)
                .ifPresent(builder::includePaths);
        resolveStringList(JwtPropertyKeys.ACCESSLOG.EXCLUDE_PATHS)
                .ifPresent(builder::excludePaths);
        config.getOptionalValue(JwtPropertyKeys.ACCESSLOG.PATTERN, String.class)
                .ifPresent(builder::pattern);
        config.getOptionalValue(JwtPropertyKeys.ACCESSLOG.ENABLED, Boolean.class)
                .ifPresent(builder::enabled);
        var resolvedConfig = builder.build();
        resolvedConfig.validate();
        return resolvedConfig;
    }

    private Optional<List<Integer>> resolveIntegerList(String key) {
        return config.getOptionalValue(key, String.class)
                .map(string -> ConfigValueParser.splitCsv(string).stream()
                        .map(s -> parseInteger(key, s))
                        .toList());
    }

    private static int parseInteger(String propertyKey, String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Invalid integer value '%s' for configuration property '%s'".formatted(value, propertyKey), e);
        }
    }

    private Optional<List<String>> resolveStringList(String key) {
        return config.getOptionalValue(key, String.class)
                .map(ConfigValueParser::splitCsv);
    }
}