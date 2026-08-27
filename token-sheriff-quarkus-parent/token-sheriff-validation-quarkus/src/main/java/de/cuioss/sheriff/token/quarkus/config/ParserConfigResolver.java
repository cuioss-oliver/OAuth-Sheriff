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

import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.tools.logging.CuiLogger;
import org.eclipse.microprofile.config.Config;

import static de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages.INFO;

/**
 * Resolver for creating {@link ParserConfig} instances from Quarkus configuration properties.
 * <p>
 * This class handles the configuration resolution for JWT parser settings, using the
 * builder pattern and delegating validation to the underlying ParserConfig builder.
 * </p>
 * <p>
 * The resolver uses builder defaults for any properties not explicitly configured,
 * ensuring consistent behavior without duplicating default value logic.
 * </p>
 * <p>
 * All validation is handled by the ParserConfig builder itself, avoiding logic
 * duplication and ensuring consistency with the core validation rules.
 * </p>
 *
 * @since 1.0
 */
public class ParserConfigResolver {

    private static final CuiLogger LOGGER = new CuiLogger(ParserConfigResolver.class);

    private final Config config;

    /**
     * Creates a new ParserConfigResolver with the specified configuration.
     *
     * @param config the configuration instance to use for property resolution
     */
    public ParserConfigResolver(Config config) {
        this.config = config;
    }

    /**
     * Resolves a ParserConfig from properties using builder defaults.
     * <p>
     * This method uses the builder pattern and relies on the builder's default values
     * for any properties not explicitly configured. The builder handles validation
     * internally, so no duplication of validation logic is needed.
     * </p>
     * <p>
     * Only properties that are explicitly configured in the application properties
     * will override the builder defaults. This ensures that default value management
     * remains centralized in the ParserConfig class.
     * </p>
     *
     * @return a ParserConfig instance configured from properties
     * @throws IllegalArgumentException if parser configuration is invalid (from builder)
     */
   
    public ParserConfig resolveParserConfig() {
        LOGGER.debug("Resolving ParserConfig from properties");

        ParserConfig.ParserConfigBuilder builder = ParserConfig.builder();

        // Use builder defaults for optional values - only set if explicitly configured
        config.getOptionalValue(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, Integer.class)
                .ifPresent(value -> {
                    builder.maxTokenSize(value);
                    LOGGER.debug("Set maxTokenSize from configuration: %s", value);
                });

        config.getOptionalValue(JwtPropertyKeys.PARSER.MAX_PAYLOAD_SIZE, Integer.class)
                .ifPresent(value -> {
                    builder.maxPayloadSize(value);
                    LOGGER.debug("Set maxPayloadSize from configuration: %s", value);
                });

        config.getOptionalValue(JwtPropertyKeys.PARSER.MAX_STRING_LENGTH, Integer.class)
                .ifPresent(value -> {
                    builder.maxStringLength(value);
                    LOGGER.debug("Set maxStringLength from configuration: %s", value);
                });

        // Let the builder validate and create the instance
        ParserConfig result = builder.build();

        LOGGER.info(INFO.RESOLVED_PARSER_CONFIG, result.getMaxTokenSize(), result.getMaxPayloadSize(), result.getMaxStringLength());

        return result;
    }
}