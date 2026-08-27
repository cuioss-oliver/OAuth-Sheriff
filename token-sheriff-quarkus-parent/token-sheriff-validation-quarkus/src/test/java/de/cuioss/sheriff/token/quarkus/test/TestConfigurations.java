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

import de.cuioss.sheriff.token.quarkus.config.JwtPropertyKeys;

import java.util.HashMap;
import java.util.Map;

/**
 * Utility class providing predefined test configurations for common JWT scenarios.
 * This class offers convenient factory methods for creating typical JWT test configurations
 * without the boilerplate of setting up individual properties.
 */
public final class TestConfigurations {

    private TestConfigurations() {
        // Utility class
    }

    /**
     * Creates a minimal valid JWT configuration with a single issuer.
     * Suitable for testing basic positive scenarios.
     *
     * @return TestConfig with minimal valid JWT configuration
     */
    public static TestConfig minimalValid() {
        return new TestConfig(Map.of(
                JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), "true",
                JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("test"), "https://test.example.com",
                JwtPropertyKeys.ISSUERS.JWKS_FILE_PATH.formatted("test"), "classpath:keys/test_public_key.jwks",
                JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted("test"), "true"
        ));
    }

    /**
     * Creates a configuration with invalid parser settings.
     * Useful for testing configuration validation error scenarios.
     *
     * @return TestConfig with invalid parser configuration
     */
    public static TestConfig invalidParser() {
        return new TestConfig(Map.of(
                JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, "-1",
                JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), "true",
                JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("test"), "https://test.example.com",
                JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted("test"), "true"
        ));
    }

    /**
     * Creates a configuration with no enabled issuers.
     * Useful for testing empty configuration scenarios.
     *
     * @return TestConfig with no enabled issuers
     */
    public static TestConfig noEnabledIssuers() {
        return new TestConfig(Map.of(
                JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), "false",
                JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("test"), "https://test.example.com"
        ));
    }

    /**
     * Creates a configuration with conflicting issuer settings.
     * Tests validation of mutually exclusive configuration options.
     *
     * @return TestConfig with conflicting issuer configuration
     */
    public static TestConfig conflictingIssuerConfig() {
        return new TestConfig(Map.of(
                JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), "true",
                JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("test"), "https://test.example.com",
                JwtPropertyKeys.ISSUERS.WELL_KNOWN_URL.formatted("test"), "https://test.example.com/.well-known/openid_configuration",
                JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted("test"), "true"
        ));
    }

    /**
     * Creates a configuration for testing JWKS endpoint scenarios.
     * Includes proper JWKS URL configuration.
     *
     * @return TestConfig with JWKS URL configuration
     */
    public static TestConfig withJwksUrl() {
        return new TestConfig(Map.of(
                JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), "true",
                JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("test"), "https://test.example.com",
                JwtPropertyKeys.ISSUERS.JWKS_URL.formatted("test"), "https://test.example.com/jwks",
                JwtPropertyKeys.ISSUERS.REFRESH_INTERVAL_SECONDS.formatted("test"), "300",
                JwtPropertyKeys.ISSUERS.CONNECT_TIMEOUT_SECONDS.formatted("test"), "5",
                JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted("test"), "true"
        ));
    }

    /**
     * Creates a configuration for testing well-known endpoint discovery.
     * Includes proper well-known URL configuration.
     *
     * @return TestConfig with well-known URL configuration
     */
    public static TestConfig withWellKnownUrl() {
        return new TestConfig(Map.of(
                JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), "true",
                JwtPropertyKeys.ISSUERS.WELL_KNOWN_URL.formatted("test"), "https://test.example.com/.well-known/openid_configuration",
                JwtPropertyKeys.ISSUERS.CONNECT_TIMEOUT_SECONDS.formatted("test"), "5",
                JwtPropertyKeys.ISSUERS.READ_TIMEOUT_SECONDS.formatted("test"), "5",
                JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted("test"), "true"
        ));
    }

    /**
     * Creates a configuration with multiple issuers for testing complex scenarios.
     * Includes both enabled and disabled issuers.
     *
     * @return TestConfig with multiple issuers
     */
    public static TestConfig multipleIssuers() {
        return new TestConfig(Map.of(
                JwtPropertyKeys.ISSUERS.ENABLED.formatted("primary"), "true",
                JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("primary"), "https://primary.example.com",
                JwtPropertyKeys.ISSUERS.JWKS_URL.formatted("primary"), "https://primary.example.com/jwks",
                JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted("primary"), "true",
                JwtPropertyKeys.ISSUERS.ENABLED.formatted("secondary"), "true",
                JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("secondary"), "https://secondary.example.com",
                JwtPropertyKeys.ISSUERS.JWKS_URL.formatted("secondary"), "https://secondary.example.com/jwks",
                JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted("secondary"), "true",
                JwtPropertyKeys.ISSUERS.ENABLED.formatted("disabled"), "false",
                JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("disabled"), "https://disabled.example.com"
        ));
    }

    /**
     * Creates a configuration with custom parser settings.
     * Useful for testing parser configuration scenarios.
     *
     * @return TestConfig with custom parser configuration
     */
    public static TestConfig customParser() {
        return new TestConfig(Map.of(
                JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, "16384",
                JwtPropertyKeys.PARSER.MAX_PAYLOAD_SIZE, "16384",
                JwtPropertyKeys.PARSER.MAX_STRING_LENGTH, "8192",
                JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), "true",
                JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("test"), "https://test.example.com",
                JwtPropertyKeys.ISSUERS.JWKS_FILE_PATH.formatted("test"), "classpath:keys/test_public_key.jwks",
                JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted("test"), "true"
        ));
    }

    /**
     * Creates an empty configuration for testing missing configuration scenarios.
     *
     * @return Empty TestConfig
     */
    public static TestConfig empty() {
        return new TestConfig(Map.of());
    }

    /**
     * Builder for creating custom test configurations with fluent API.
     *
     * @return new TestConfigBuilder instance
     */
    public static TestConfigBuilder builder() {
        return new TestConfigBuilder();
    }

    /**
     * Builder class for creating custom test configurations with a fluent API.
     */
    public static class TestConfigBuilder {
        private final Map<String, String> properties = new HashMap<>();

        /**
         * Adds an issuer configuration to the builder.
         *
         * @param issuerName the name of the issuer
         * @return IssuerConfigBuilder for configuring the issuer
         */
        public IssuerConfigBuilder withIssuer(String issuerName) {
            return new IssuerConfigBuilder(this, issuerName);
        }

        /**
         * Adds parser configuration to the builder.
         *
         * @return ParserConfigBuilder for configuring the parser
         */
        public ParserConfigBuilder withParser() {
            return new ParserConfigBuilder(this);
        }

        /**
         * Adds a custom property to the configuration.
         *
         * @param key   the property key
         * @param value the property value
         * @return this builder
         */
        public TestConfigBuilder withProperty(String key, String value) {
            properties.put(key, value);
            return this;
        }

        /**
         * Builds the TestConfig with all configured properties.
         *
         * @return new TestConfig instance
         */
        public TestConfig build() {
            return new TestConfig(new HashMap<>(properties));
        }

        void addProperty(String key, String value) {
            properties.put(key, value);
        }
    }

    /**
     * Builder for configuring issuer-specific properties.
     */
    public static class IssuerConfigBuilder {
        private final TestConfigBuilder parent;
        private final String issuerName;

        IssuerConfigBuilder(TestConfigBuilder parent, String issuerName) {
            this.parent = parent;
            this.issuerName = issuerName;
        }

        /**
         * Sets whether the issuer is enabled.
         *
         * @param enabled true if enabled
         * @return this builder
         */
        public IssuerConfigBuilder enabled(boolean enabled) {
            parent.addProperty(JwtPropertyKeys.ISSUERS.ENABLED.formatted(issuerName), String.valueOf(enabled));
            return this;
        }

        /**
         * Sets the issuer identifier.
         *
         * @param identifier the issuer identifier URL
         * @return this builder
         */
        public IssuerConfigBuilder identifier(String identifier) {
            parent.addProperty(JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted(issuerName), identifier);
            return this;
        }

        /**
         * Sets the public key location.
         *
         * @param location the public key file location
         * @return this builder
         */
        public IssuerConfigBuilder publicKeyLocation(String location) {
            parent.addProperty(JwtPropertyKeys.ISSUERS.JWKS_FILE_PATH.formatted(issuerName), location);
            return this;
        }

        /**
         * Sets the JWKS URL.
         *
         * @param url the JWKS endpoint URL
         * @return this builder
         */
        public IssuerConfigBuilder jwksUrl(String url) {
            parent.addProperty(JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(issuerName), url);
            return this;
        }

        /**
         * Disables audience validation for this issuer.
         *
         * @param disabled true to disable audience validation
         * @return this builder
         */
        public IssuerConfigBuilder audienceValidationDisabled(boolean disabled) {
            parent.addProperty(JwtPropertyKeys.ISSUERS.AUDIENCE_VALIDATION_DISABLED.formatted(issuerName), String.valueOf(disabled));
            return this;
        }

        /**
         * Sets the well-known discovery URL.
         *
         * @param url the well-known endpoint URL
         * @return this builder
         */
        public IssuerConfigBuilder wellKnownUrl(String url) {
            parent.addProperty(JwtPropertyKeys.ISSUERS.WELL_KNOWN_URL.formatted(issuerName), url);
            return this;
        }

        /**
         * Configures JWKS refresh interval.
         *
         * @param seconds refresh interval in seconds
         * @return this builder
         */
        public IssuerConfigBuilder jwksRefreshInterval(int seconds) {
            parent.addProperty(JwtPropertyKeys.ISSUERS.REFRESH_INTERVAL_SECONDS.formatted(issuerName), String.valueOf(seconds));
            return this;
        }

        /**
         * Returns to the parent builder.
         *
         * @return parent TestConfigBuilder
         */
        public TestConfigBuilder and() {
            return parent;
        }

        /**
         * Builds the configuration directly from this issuer builder.
         *
         * @return new TestConfig instance
         */
        public TestConfig build() {
            return parent.build();
        }
    }

    /**
     * Builder for configuring parser-specific properties.
     */
    public static class ParserConfigBuilder {
        private final TestConfigBuilder parent;

        ParserConfigBuilder(TestConfigBuilder parent) {
            this.parent = parent;
        }

        /**
         * Sets the maximum token size in bytes.
         *
         * @param bytes maximum token size
         * @return this builder
         */
        public ParserConfigBuilder maxTokenSize(int bytes) {
            parent.addProperty(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, String.valueOf(bytes));
            return this;
        }

        /**
         * Sets the maximum payload size in bytes.
         *
         * @param bytes maximum payload size
         * @return this builder
         */
        public ParserConfigBuilder maxPayloadSize(int bytes) {
            parent.addProperty(JwtPropertyKeys.PARSER.MAX_PAYLOAD_SIZE, String.valueOf(bytes));
            return this;
        }

        /**
         * Sets the maximum string length for JSON parsing in bytes.
         *
         * @param length maximum string length
         * @return this builder
         */
        public ParserConfigBuilder maxStringLength(int length) {
            parent.addProperty(JwtPropertyKeys.PARSER.MAX_STRING_LENGTH, String.valueOf(length));
            return this;
        }

        /**
         * Returns to the parent builder.
         *
         * @return parent TestConfigBuilder
         */
        public TestConfigBuilder and() {
            return parent;
        }

        /**
         * Builds the configuration directly from this parser builder.
         *
         * @return new TestConfig instance
         */
        public TestConfig build() {
            return parent.build();
        }
    }
}