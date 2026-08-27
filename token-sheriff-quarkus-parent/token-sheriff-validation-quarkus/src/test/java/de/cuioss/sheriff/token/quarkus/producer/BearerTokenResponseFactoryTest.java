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
package de.cuioss.sheriff.token.quarkus.producer;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.ClaimControlParameter;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link BearerTokenResponseFactory} OAuth compliance.
 * <p>
 * Validates OAuth 2.0 Bearer Token specification (RFC 6750) and OAuth Step-Up
 * Authentication Challenge compliance of error response generation from
 * {@link BearerTokenResult} objects.
 *
 * @author Oliver Wolff
 */
@DisplayName("BearerTokenResponseFactory Tests")
class BearerTokenResponseFactoryTest {

    @Nested
    @DisplayName("createResponse() with FULLY_VERIFIED status")
    class CreateResponseWithFullyVerifiedStatus {

        @Test
        @DisplayName("should throw IllegalStateException for FULLY_VERIFIED")
        void shouldThrowForFullyVerified() {
            var tokenContent = createTestToken();
            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.FULLY_VERIFIED)
                    .accessTokenContent(tokenContent)
                    .build();

            assertThrows(IllegalStateException.class, () -> BearerTokenResponseFactory.createResponse(result));
        }
    }

    @Nested
    @DisplayName("createResponse() with NO_TOKEN_GIVEN status")
    class CreateResponseWithNoTokenGivenStatus {

        @Test
        @DisplayName("should return 401 Unauthorized with basic WWW-Authenticate header")
        void shouldReturn401WithBasicWWWAuthenticate() {
            var result = BearerTokenResult.noTokenGiven(
                    Set.of(), Set.of(), Set.of());

            Response response = BearerTokenResponseFactory.createResponse(result);

            assertEquals(401, response.getStatus());
            assertEquals("no-store, no-cache, must-revalidate", response.getHeaderString("Cache-Control"));
            assertEquals("no-cache", response.getHeaderString("Pragma"));
            assertEquals("Bearer realm=\"protected-resource\"", response.getHeaderString("WWW-Authenticate"));
        }
    }

    @Nested
    @DisplayName("createResponse() with PARSING_ERROR status")
    class CreateResponseWithParsingErrorStatus {

        @Test
        @DisplayName("should return 401 Unauthorized with invalid_token error")
        void shouldReturn401WithInvalidTokenError() {
            var exception = new TokenValidationException(
                    SecurityEventCounter.EventType.INVALID_JWT_FORMAT, "Token format is invalid");
            var result = BearerTokenResult.parsingError(exception,
                    Set.of(), Set.of(), Set.of());

            Response response = BearerTokenResponseFactory.createResponse(result);

            assertEquals(401, response.getStatus());
            assertEquals("no-store, no-cache, must-revalidate", response.getHeaderString("Cache-Control"));
            assertEquals("no-cache", response.getHeaderString("Pragma"));

            String wwwAuthenticate = response.getHeaderString("WWW-Authenticate");
            assertNotNull(wwwAuthenticate);
            assertTrue(wwwAuthenticate.contains("Bearer realm=\"protected-resource\""));
            assertTrue(wwwAuthenticate.contains("error=\"invalid_token\""));
            assertTrue(wwwAuthenticate.contains("error_description=\"The access token is invalid\""));
        }

        @Test
        @DisplayName("should handle null error message gracefully")
        void shouldHandleNullErrorMessage() {
            var exception = new TokenValidationException(
                    SecurityEventCounter.EventType.INVALID_JWT_FORMAT, null);
            var result = BearerTokenResult.parsingError(exception,
                    Set.of(), Set.of(), Set.of());

            Response response = BearerTokenResponseFactory.createResponse(result);

            assertEquals(401, response.getStatus());
            String wwwAuthenticate = response.getHeaderString("WWW-Authenticate");
            assertTrue(wwwAuthenticate.contains("error_description=\"The access token is invalid\""));
        }
    }

    @Nested
    @DisplayName("createResponse() with CONSTRAINT_VIOLATION status")
    class CreateResponseWithConstraintViolationStatus {

        @Test
        @DisplayName("should return 401 Unauthorized for scope violation with insufficient_scope error")
        void shouldReturn401ForScopeViolation() {
            var requiredScopes = Set.of("read", "write");
            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(requiredScopes)
                    .missingScopes(requiredScopes)
                    .requiredRoles(Set.of())
                    .requiredGroups(Set.of())
                    .build();

            Response response = BearerTokenResponseFactory.createResponse(result);

            assertEquals(401, response.getStatus());
            assertEquals("no-store, no-cache, must-revalidate", response.getHeaderString("Cache-Control"));
            assertEquals("no-cache", response.getHeaderString("Pragma"));

            String wwwAuthenticate = response.getHeaderString("WWW-Authenticate");
            assertNotNull(wwwAuthenticate);
            assertTrue(wwwAuthenticate.contains("Bearer realm=\"protected-resource\""));
            assertTrue(wwwAuthenticate.contains("error=\"insufficient_scope\""));
            assertTrue(wwwAuthenticate.contains("error_description=\"The request requires higher privileges than provided by the access token\""));
            // Check both possible orders since Set doesn't guarantee ordering
            boolean hasCorrectScope = wwwAuthenticate.contains("scope=\"read write\"") ||
                    wwwAuthenticate.contains("scope=\"write read\"");
            assertTrue(hasCorrectScope, "WWW-Authenticate header should contain correctly ordered scopes: " + wwwAuthenticate);
        }

        @Test
        @DisplayName("should return 403 Forbidden for role violation with insufficient_privileges error")
        void shouldReturn403ForRoleViolation() {
            var requiredRoles = Set.of("admin", "manager");
            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(Set.of())
                    .requiredRoles(requiredRoles)
                    .missingRoles(requiredRoles)
                    .requiredGroups(Set.of())
                    .build();

            Response response = BearerTokenResponseFactory.createResponse(result);

            assertEquals(403, response.getStatus());
            assertEquals("no-store, no-cache, must-revalidate", response.getHeaderString("Cache-Control"));
            assertEquals("no-cache", response.getHeaderString("Pragma"));

            String wwwAuthenticate = response.getHeaderString("WWW-Authenticate");
            assertNotNull(wwwAuthenticate);
            assertTrue(wwwAuthenticate.contains("Bearer realm=\"protected-resource\""));
            assertTrue(wwwAuthenticate.contains("error=\"insufficient_privileges\""));
            assertTrue(wwwAuthenticate.contains("error_description=\"The request requires higher privileges than provided by the access token\""));
            // Check both possible orders since Set doesn't guarantee ordering
            boolean hasCorrectRoles = wwwAuthenticate.contains("required_roles=\"admin manager\"") ||
                    wwwAuthenticate.contains("required_roles=\"manager admin\"");
            assertTrue(hasCorrectRoles, "WWW-Authenticate header should contain correctly ordered roles: " + wwwAuthenticate);
        }

        @Test
        @DisplayName("should return 403 Forbidden for group violation with insufficient_privileges error")
        void shouldReturn403ForGroupViolation() {
            var requiredGroups = Set.of("developers", "testers");
            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(Set.of())
                    .requiredRoles(Set.of())
                    .requiredGroups(requiredGroups)
                    .missingGroups(requiredGroups)
                    .build();

            Response response = BearerTokenResponseFactory.createResponse(result);

            assertEquals(403, response.getStatus());

            String wwwAuthenticate = response.getHeaderString("WWW-Authenticate");
            assertNotNull(wwwAuthenticate);
            assertTrue(wwwAuthenticate.contains("Bearer realm=\"protected-resource\""));
            assertTrue(wwwAuthenticate.contains("error=\"insufficient_privileges\""));
            // Check both possible orders since Set doesn't guarantee ordering
            boolean hasCorrectGroups = wwwAuthenticate.contains("required_groups=\"developers testers\"") ||
                    wwwAuthenticate.contains("required_groups=\"testers developers\"");
            assertTrue(hasCorrectGroups, "WWW-Authenticate header should contain correctly ordered groups: " + wwwAuthenticate);
        }

        @Test
        @DisplayName("should return 403 Forbidden for combined role and group violation")
        void shouldReturn403ForCombinedRoleGroupViolation() {
            var requiredRoles = Set.of("admin");
            var requiredGroups = Set.of("developers");
            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(Set.of())
                    .requiredRoles(requiredRoles)
                    .missingRoles(requiredRoles)
                    .requiredGroups(requiredGroups)
                    .missingGroups(requiredGroups)
                    .build();

            Response response = BearerTokenResponseFactory.createResponse(result);

            assertEquals(403, response.getStatus());

            String wwwAuthenticate = response.getHeaderString("WWW-Authenticate");
            assertNotNull(wwwAuthenticate);
            assertTrue(wwwAuthenticate.contains("required_roles=\"admin\""));
            assertTrue(wwwAuthenticate.contains("required_groups=\"developers\""));
        }

        @Test
        @DisplayName("should prioritize scope violation over role/group violation")
        void shouldPrioritizeScopeViolation() {
            var requiredScopes = Set.of("read");
            var requiredRoles = Set.of("admin");
            var requiredGroups = Set.of("developers");
            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(requiredScopes)
                    .missingScopes(requiredScopes)
                    .requiredRoles(requiredRoles)
                    .missingRoles(requiredRoles)
                    .requiredGroups(requiredGroups)
                    .missingGroups(requiredGroups)
                    .build();

            Response response = BearerTokenResponseFactory.createResponse(result);

            // Should return 401 for scope violation, not 403 for role/group
            assertEquals(401, response.getStatus());

            String wwwAuthenticate = response.getHeaderString("WWW-Authenticate");
            assertTrue(wwwAuthenticate.contains("error=\"insufficient_scope\""));
            assertTrue(wwwAuthenticate.contains("scope=\"read\""));
        }
    }

    @Nested
    @DisplayName("Quote Escaping")
    class QuoteEscaping {

        @Test
        @DisplayName("should escape quotes in scope names")
        void shouldEscapeQuotesInScopeNames() {
            var requiredScopes = Set.of("read:\"special\"", "write");
            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(requiredScopes)
                    .missingScopes(requiredScopes)
                    .requiredRoles(Set.of())
                    .requiredGroups(Set.of())
                    .build();

            String wwwAuthenticate = BearerTokenResponseFactory.createResponse(result).getHeaderString("WWW-Authenticate");

            // Check both possible orders since Set doesn't guarantee ordering
            boolean hasCorrectScope = wwwAuthenticate.contains("scope=\"read:\\\"special\\\" write\"") ||
                    wwwAuthenticate.contains("scope=\"write read:\\\"special\\\"\"");
            assertTrue(hasCorrectScope, "WWW-Authenticate header should contain correctly escaped scopes: " + wwwAuthenticate);
        }

        @Test
        @DisplayName("should escape quotes in role names")
        void shouldEscapeQuotesInRoleNames() {
            var requiredRoles = Set.of("admin:\"special\"");
            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(Set.of())
                    .requiredRoles(requiredRoles)
                    .missingRoles(requiredRoles)
                    .requiredGroups(Set.of())
                    .build();

            String wwwAuthenticate = BearerTokenResponseFactory.createResponse(result).getHeaderString("WWW-Authenticate");
            assertTrue(wwwAuthenticate.contains("required_roles=\"admin:\\\"special\\\"\""));
        }
    }

    @Nested
    @DisplayName("Security Headers")
    class SecurityHeaders {

        @Test
        @DisplayName("should include security headers in all responses")
        void shouldIncludeSecurityHeadersInAllResponses() {
            var testCases = Map.of(
                    "noToken", BearerTokenResult.noTokenGiven(Set.of(), Set.of(), Set.of()),
                    "parsingError", BearerTokenResult.parsingError(new TokenValidationException(SecurityEventCounter.EventType.INVALID_JWT_FORMAT, "test"), Set.of(), Set.of(), Set.of()),
                    "constraintViolation", BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(Set.of("read"))
                    .missingScopes(Set.of("read"))
                    .requiredRoles(Set.of())
                    .requiredGroups(Set.of())
                    .build()
            );

            testCases.forEach((name, result) -> {
                var response = BearerTokenResponseFactory.createResponse(result);
                assertEquals("no-store, no-cache, must-revalidate", response.getHeaderString("Cache-Control"),
                        name + " should have Cache-Control header");
                assertEquals("no-cache", response.getHeaderString("Pragma"),
                        name + " should have Pragma header");
            });
        }
    }

    private AccessTokenContent createTestToken() {
        TestTokenHolder holder = new TestTokenHolder(TokenType.ACCESS_TOKEN,
                ClaimControlParameter.defaultForTokenType(TokenType.ACCESS_TOKEN));
        return holder.asAccessTokenContent();
    }
}