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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JwtPropertyKeys")
class JwtPropertyKeysTest {

    @Nested
    @DisplayName("Base Properties")
    class BaseProperties {

        @Test
        @DisplayName("should have correct prefix")
        void shouldHaveCorrectPrefix() {
            assertEquals("sheriff.token", JwtPropertyKeys.PREFIX);
        }

        @Test
        @DisplayName("should have correct dot jwks suffix")
        void shouldHaveCorrectDotJwksSuffix() {
            assertEquals(".jwks", JwtPropertyKeys.DOT_JWKS);
        }
    }

    @Nested
    @DisplayName("Parser Properties")
    class ParserProperties {

        @Test
        @DisplayName("should have correct base path")
        void shouldHaveCorrectBasePath() {
            assertEquals("sheriff.token.parser", JwtPropertyKeys.PARSER.BASE);
        }

        @Test
        @DisplayName("should have parser properties with correct prefix")
        void shouldHaveParserPropertiesWithCorrectPrefix() {
            assertTrue(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE.startsWith(JwtPropertyKeys.PARSER.BASE));
            assertTrue(JwtPropertyKeys.PARSER.MAX_PAYLOAD_SIZE.startsWith(JwtPropertyKeys.PARSER.BASE));
            assertTrue(JwtPropertyKeys.PARSER.MAX_STRING_LENGTH.startsWith(JwtPropertyKeys.PARSER.BASE));
        }
    }

    @Nested
    @DisplayName("Issuer Properties")
    class IssuerProperties {

        @Test
        @DisplayName("should format issuer base property correctly")
        void shouldFormatIssuerBasePropertyCorrectly() {
            var issuerName = "default";
            var expected = "sheriff.token.issuers.default.";
            var actual = JwtPropertyKeys.ISSUERS.BASE.formatted(issuerName);

            assertEquals(expected, actual);
        }

        @Test
        @DisplayName("should format issuer enabled property correctly")
        void shouldFormatIssuerEnabledPropertyCorrectly() {
            var issuerName = "keycloak";
            var expected = "sheriff.token.issuers.keycloak.enabled";
            var actual = JwtPropertyKeys.ISSUERS.ENABLED.formatted(issuerName);

            assertEquals(expected, actual);
        }

        @Test
        @DisplayName("should format JWKS URL property correctly")
        void shouldFormatJwksUrlPropertyCorrectly() {
            var issuerName = "auth0";
            var expected = "sheriff.token.issuers.auth0.jwks.http.url";
            var actual = JwtPropertyKeys.ISSUERS.JWKS_URL.formatted(issuerName);

            assertEquals(expected, actual);
        }

        @Test
        @DisplayName("should format well-known URL property correctly")
        void shouldFormatWellKnownUrlPropertyCorrectly() {
            var issuerName = "oidc";
            var expected = "sheriff.token.issuers.oidc.jwks.http.well-known-url";
            var actual = JwtPropertyKeys.ISSUERS.WELL_KNOWN_URL.formatted(issuerName);

            assertEquals(expected, actual);
        }
    }

    @Nested
    @DisplayName("Keycloak Properties")
    class KeycloakProperties {

        @Test
        @DisplayName("should have correct keycloak base path")
        void shouldHaveCorrectKeycloakBasePath() {
            assertEquals("sheriff.token.keycloak", JwtPropertyKeys.KEYCLOAK.BASE);
        }

        @Test
        @DisplayName("should have correct default roles mapper enabled property")
        void shouldHaveCorrectDefaultRolesMapperEnabledProperty() {
            assertEquals("sheriff.token.keycloak.default-roles-mapper.enabled",
                    JwtPropertyKeys.KEYCLOAK.DEFAULT_ROLES_MAPPER_ENABLED);
        }

        @Test
        @DisplayName("should have correct default groups mapper enabled property")
        void shouldHaveCorrectDefaultGroupsMapperEnabledProperty() {
            assertEquals("sheriff.token.keycloak.default-groups-mapper.enabled",
                    JwtPropertyKeys.KEYCLOAK.DEFAULT_GROUPS_MAPPER_ENABLED);
        }
    }

    @Nested
    @DisplayName("Health Properties")
    class HealthProperties {

        @Test
        @DisplayName("should have correct health base path")
        void shouldHaveCorrectHealthBasePath() {
            assertEquals("sheriff.token.health", JwtPropertyKeys.HEALTH.BASE);
        }

        @Test
        @DisplayName("should have correct JWKS health properties")
        void shouldHaveCorrectJwksHealthProperties() {
            assertEquals("sheriff.token.health.jwks", JwtPropertyKeys.HEALTH.JWKS.BASE);
            assertTrue(JwtPropertyKeys.HEALTH.JWKS.CACHE_SECONDS.startsWith(JwtPropertyKeys.HEALTH.JWKS.BASE));
        }
    }
}