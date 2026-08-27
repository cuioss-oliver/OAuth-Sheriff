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
package de.cuioss.sheriff.token.client.quarkus.config;

import de.cuioss.sheriff.token.client.config.ClientAuthMethod;
import de.cuioss.sheriff.token.client.config.ClientConfiguration;
import org.eclipse.microprofile.config.Config;

import java.util.List;

/**
 * Maps MicroProfile {@link Config} values under the {@link ClientRuntimeConfig} keys to the
 * framework-agnostic engine {@link ClientConfiguration} ({@code CLIENT-21}).
 * <p>
 * Values are read through {@code Config.getOptionalValue}, so the mapping never fails eagerly at
 * container startup: an application that has the client extension on the classpath but does not
 * configure it simply reports {@link #isConfigured(Config) not configured}. The mapping enforces the
 * required fields only when {@link #map(Config)} is actually invoked (that is, when a bean the engine
 * exposes is used).
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public final class ClientConfigMapper {

    private static final String DEFAULT_AUTH_METHOD = ClientAuthMethod.CLIENT_SECRET_BASIC.getMetadataValue();

    private ClientConfigMapper() {
        // utility class — never instantiated
    }

    /**
     * Reports whether enough configuration is present to build a {@link ClientConfiguration}. A client
     * is configured only when both {@link ClientRuntimeConfig#ISSUER} and
     * {@link ClientRuntimeConfig#CLIENT_ID} are set.
     *
     * @param config the MicroProfile config to inspect; must not be {@code null}
     * @return {@code true} when the client is configured
     */
    public static boolean isConfigured(Config config) {
        return config.getOptionalValue(ClientRuntimeConfig.ISSUER, String.class).isPresent()
                && config.getOptionalValue(ClientRuntimeConfig.CLIENT_ID, String.class).isPresent();
    }

    /**
     * Builds the engine {@link ClientConfiguration} from the configured MicroProfile values.
     *
     * @param config the MicroProfile config to read; must not be {@code null}
     * @return the mapped, immutable client configuration
     * @throws IllegalStateException    when a required key ({@link ClientRuntimeConfig#ISSUER} or
     *                                  {@link ClientRuntimeConfig#CLIENT_ID}) is missing
     * @throws IllegalArgumentException when {@link ClientRuntimeConfig#AUTH_METHOD} names an
     *                                  unrecognised authentication method, or when
     *                                  {@link ClientRuntimeConfig#DISCOVERY_DOCUMENT_MAX_SIZE} is not
     *                                  positive
     */
    public static ClientConfiguration map(Config config) {
        String issuer = requiredValue(config, ClientRuntimeConfig.ISSUER);
        String clientId = requiredValue(config, ClientRuntimeConfig.CLIENT_ID);

        ClientConfiguration.ClientConfigurationBuilder builder = ClientConfiguration.builder()
                .issuer(issuer)
                .clientId(clientId)
                .authMethod(resolveAuthMethod(config))
                .allowInsecureHttp(config.getOptionalValue(ClientRuntimeConfig.ALLOW_INSECURE_HTTP, Boolean.class)
                        .orElse(Boolean.FALSE));

        config.getOptionalValue(ClientRuntimeConfig.DISCOVERY_DOCUMENT_MAX_SIZE, Integer.class)
                .ifPresent(builder::discoveryDocumentMaxSize);
        config.getOptionalValue(ClientRuntimeConfig.CLIENT_SECRET, String.class).ifPresent(builder::clientSecret);
        config.getOptionalValue(ClientRuntimeConfig.REDIRECT_URI, String.class).ifPresent(builder::redirectUri);
        resolveScopes(config).forEach(builder::scope);

        return builder.build();
    }

    private static String requiredValue(Config config, String key) {
        return config.getOptionalValue(key, String.class)
                .orElseThrow(() -> new IllegalStateException(
                        "Required Token-Sheriff client property '" + key + "' is not configured"));
    }

    private static ClientAuthMethod resolveAuthMethod(Config config) {
        String value = config.getOptionalValue(ClientRuntimeConfig.AUTH_METHOD, String.class)
                .orElse(DEFAULT_AUTH_METHOD);
        return ClientAuthMethod.fromMetadataValue(value)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Unknown '" + ClientRuntimeConfig.AUTH_METHOD + "' value '" + value
                                + "'; expected an RFC 8414 token_endpoint_auth_methods value"));
    }

    private static List<String> resolveScopes(Config config) {
        return config.getOptionalValues(ClientRuntimeConfig.SCOPES, String.class).orElse(List.of());
    }
}
