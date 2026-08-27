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

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter.EventType;
import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.ClaimControlParameter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive unit tests for {@link BearerTokenResult} class.
 * Tests all methods, builders, static factory methods, and edge cases.
 *
 * @author Oliver Wolff
 */
@DisplayName("BearerTokenResult Unit Tests")
class BearerTokenResultTest {

    @Nested
    @DisplayName("Static Factory Methods")
    class StaticFactoryMethods {

        @Test
        @DisplayName("builder should create FULLY_VERIFIED result with no missing attributes")
        void builderShouldCreateFullyVerifiedResult() {
            var tokenContent = createTestToken();
            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.FULLY_VERIFIED)
                    .accessTokenContent(tokenContent)
                    .build();

            assertEquals(BearerTokenStatus.FULLY_VERIFIED, result.getStatus());
            assertTrue(result.getAccessTokenContent().isPresent());
            assertEquals(tokenContent, result.getAccessTokenContent().get());
            assertTrue(result.getRequiredScopes().isEmpty());
            assertTrue(result.getRequiredRoles().isEmpty());
            assertTrue(result.getRequiredGroups().isEmpty());
            assertFalse(result.getErrorEventType().isPresent());
            assertFalse(result.getErrorMessage().isPresent());
        }

        @Test
        @DisplayName("parsingError() should create PARSING_ERROR result with exception details")
        void parsingErrorShouldCreateParsingErrorResult() {
            var exception = new TokenValidationException(EventType.INVALID_JWT_FORMAT, "Invalid token format");
            var requiredScopes = Set.of("read", "write");
            var requiredRoles = Set.of("admin");
            var requiredGroups = Set.of("managers");

            var result = BearerTokenResult.parsingError(exception, requiredScopes, requiredRoles, requiredGroups);

            assertEquals(BearerTokenStatus.PARSING_ERROR, result.getStatus());
            assertFalse(result.getAccessTokenContent().isPresent());
            assertEquals(requiredScopes, result.getRequiredScopes());
            assertEquals(requiredRoles, result.getRequiredRoles());
            assertEquals(requiredGroups, result.getRequiredGroups());
            assertTrue(result.getErrorEventType().isPresent());
            assertEquals(EventType.INVALID_JWT_FORMAT, result.getErrorEventType().get());
            assertTrue(result.getErrorMessage().isPresent());
            assertEquals("Invalid token format", result.getErrorMessage().get());
        }

        @Test
        @DisplayName("builder should create CONSTRAINT_VIOLATION result with missing attributes")
        void constraintViolationShouldCreateConstraintViolationResult() {
            var requiredScopes = Set.of("write");
            var requiredRoles = Set.of("admin");
            var requiredGroups = Set.of("managers");

            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(requiredScopes)
                    .requiredRoles(requiredRoles)
                    .requiredGroups(requiredGroups)
                    .build();

            assertEquals(BearerTokenStatus.CONSTRAINT_VIOLATION, result.getStatus());
            assertFalse(result.getAccessTokenContent().isPresent());
            assertEquals(requiredScopes, result.getRequiredScopes());
            assertEquals(requiredRoles, result.getRequiredRoles());
            assertEquals(requiredGroups, result.getRequiredGroups());
            assertFalse(result.getErrorEventType().isPresent());
            assertFalse(result.getErrorMessage().isPresent());
        }

        @Test
        @DisplayName("noTokenGiven() should create NO_TOKEN_GIVEN result with required attributes as missing")
        void noTokenGivenShouldCreateNoTokenGivenResult() {
            var requiredScopes = Set.of("read");
            var requiredRoles = Set.of("user");
            var requiredGroups = Set.of("group");

            var result = BearerTokenResult.noTokenGiven(requiredScopes, requiredRoles, requiredGroups);

            assertEquals(BearerTokenStatus.NO_TOKEN_GIVEN, result.getStatus());
            assertFalse(result.getAccessTokenContent().isPresent());
            assertEquals(requiredScopes, result.getRequiredScopes());
            assertEquals(requiredRoles, result.getRequiredRoles());
            assertEquals(requiredGroups, result.getRequiredGroups());
            assertFalse(result.getErrorEventType().isPresent());
            assertFalse(result.getErrorMessage().isPresent());
        }

    }

    @Nested
    @DisplayName("Builder Helper Methods")
    class BuilderHelperMethods {


        @Test
        @DisplayName("parsingError() should configure result with exception details")
        void parsingErrorShouldConfigureBuilder() {
            var exception = new TokenValidationException(EventType.INVALID_JWT_FORMAT, "Bad signature");

            var result = BearerTokenResult.parsingError(exception, Set.of(), Set.of(), Set.of());

            assertEquals(BearerTokenStatus.PARSING_ERROR, result.getStatus());
            assertTrue(result.getErrorEventType().isPresent());
            assertEquals(EventType.INVALID_JWT_FORMAT, result.getErrorEventType().get());
            assertTrue(result.getErrorMessage().isPresent());
            assertEquals("Bad signature", result.getErrorMessage().get());
        }
    }

    @Nested
    @DisplayName("Authorization Status Methods")
    class AuthorizationStatusMethods {

        @Test
        @DisplayName("isSuccessfullyAuthorized() should return true only for FULLY_VERIFIED")
        void isSuccessfullyAuthorizedShouldReturnTrueOnlyForFullyVerified() {
            var successResult = BearerTokenResult.builder()
                    .status(BearerTokenStatus.FULLY_VERIFIED)
                    .accessTokenContent(createTestToken())
                    .build();
            assertTrue(successResult.isSuccessfullyAuthorized());

            var failureResult = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(Set.of("scope"))
                    .requiredRoles(Set.of())
                    .requiredGroups(Set.of())
                    .build();
            assertFalse(failureResult.isSuccessfullyAuthorized());
        }

        @Test
        @DisplayName("isNotSuccessfullyAuthorized() should return true for all non-FULLY_VERIFIED status")
        void isNotSuccessfullyAuthorizedShouldReturnTrueForNonFullyVerified() {
            var successResult = BearerTokenResult.builder()
                    .status(BearerTokenStatus.FULLY_VERIFIED)
                    .accessTokenContent(createTestToken())
                    .build();
            assertFalse(successResult.isNotSuccessfullyAuthorized());

            var failureResult = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(Set.of("scope"))
                    .requiredRoles(Set.of())
                    .requiredGroups(Set.of())
                    .build();
            assertTrue(failureResult.isNotSuccessfullyAuthorized());
        }

        @Test
        @DisplayName("authorization status methods should be opposites")
        void authorizationStatusMethodsShouldBeOpposites() {
            for (BearerTokenStatus status : BearerTokenStatus.values()) {
                var result = createResultWithStatus(status);
                assertNotEquals(result.isSuccessfullyAuthorized(), result.isNotSuccessfullyAuthorized(),
                        "Methods should return opposite values for status: " + status);
            }
        }
    }

    @Nested
    @DisplayName("Direct Builder Usage")
    class DirectBuilderUsage {

        @Test
        @DisplayName("builder() should allow direct construction")
        void builderShouldAllowDirectConstruction() {
            var tokenContent = createTestToken();
            var requiredScopes = Set.of("write");
            var requiredRoles = Set.of("admin");
            var requiredGroups = Set.of("managers");

            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .accessTokenContent(tokenContent)
                    .requiredScopes(requiredScopes)
                    .requiredRoles(requiredRoles)
                    .requiredGroups(requiredGroups)
                    .build();

            assertEquals(BearerTokenStatus.CONSTRAINT_VIOLATION, result.getStatus());
            assertTrue(result.getAccessTokenContent().isPresent());
            assertEquals(tokenContent, result.getAccessTokenContent().get());
            assertEquals(requiredScopes, result.getRequiredScopes());
            assertEquals(requiredRoles, result.getRequiredRoles());
            assertEquals(requiredGroups, result.getRequiredGroups());
        }

        @Test
        @DisplayName("builder() should use default empty sets for missing attributes")
        void builderShouldUseDefaultEmptySets() {
            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.FULLY_VERIFIED)
                    .build();

            assertEquals(BearerTokenStatus.FULLY_VERIFIED, result.getStatus());
            assertTrue(result.getRequiredScopes().isEmpty());
            assertTrue(result.getRequiredRoles().isEmpty());
            assertTrue(result.getRequiredGroups().isEmpty());
        }

        @Test
        @DisplayName("builder() should allow setting error details individually")
        void builderShouldAllowSettingErrorDetailsIndividually() {
            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.PARSING_ERROR)
                    .errorEventType(EventType.INVALID_JWT_FORMAT)
                    .errorMessage("Custom error message")
                    .build();

            assertEquals(BearerTokenStatus.PARSING_ERROR, result.getStatus());
            assertTrue(result.getErrorEventType().isPresent());
            assertEquals(EventType.INVALID_JWT_FORMAT, result.getErrorEventType().get());
            assertTrue(result.getErrorMessage().isPresent());
            assertEquals("Custom error message", result.getErrorMessage().get());
        }
    }

    @Nested
    @DisplayName("Edge Cases and Error Handling")
    class EdgeCasesAndErrorHandling {

        @Test
        @DisplayName("factory methods should handle empty sets gracefully")
        void factoryMethodsShouldHandleEmptySets() {
            Set<String> emptySet = Set.of();
            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(emptySet)
                    .requiredRoles(emptySet)
                    .requiredGroups(emptySet)
                    .build();

            assertEquals(BearerTokenStatus.CONSTRAINT_VIOLATION, result.getStatus());
            assertTrue(result.getRequiredScopes().isEmpty());
            assertTrue(result.getRequiredRoles().isEmpty());
            assertTrue(result.getRequiredGroups().isEmpty());
        }
    }

    @Nested
    @DisplayName("Serialization and Equality")
    class SerializationAndEquality {

        @Test
        @DisplayName("results with same data should be equal")
        void resultsWithSameDataShouldBeEqual() {
            var result1 = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(Set.of("scope"))
                    .requiredRoles(Set.of("role"))
                    .requiredGroups(Set.of("group"))
                    .build();
            var result2 = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(Set.of("scope"))
                    .requiredRoles(Set.of("role"))
                    .requiredGroups(Set.of("group"))
                    .build();

            assertEquals(result1, result2);
            assertEquals(result1.hashCode(), result2.hashCode());
        }

        @Test
        @DisplayName("results with different data should not be equal")
        void resultsWithDifferentDataShouldNotBeEqual() {
            var result1 = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(Set.of("scope1"))
                    .requiredRoles(Set.of())
                    .requiredGroups(Set.of())
                    .build();
            var result2 = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(Set.of("scope2"))
                    .requiredRoles(Set.of())
                    .requiredGroups(Set.of())
                    .build();

            assertNotEquals(result1, result2);
        }

        @Test
        @DisplayName("toString should provide meaningful output")
        void toStringShouldProvideMeaningfulOutput() {
            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(Set.of("scope"))
                    .requiredRoles(Set.of("role"))
                    .requiredGroups(Set.of("group"))
                    .build();
            var toString = result.toString();

            assertNotNull(toString);
            assertTrue(toString.contains("CONSTRAINT_VIOLATION"));
            assertTrue(toString.contains("scope"));
            assertTrue(toString.contains("role"));
            assertTrue(toString.contains("group"));
        }
    }

    @Nested
    @DisplayName("createErrorResponse() Method")
    class CreateErrorResponseMethod {

        @Test
        @DisplayName("should throw IllegalStateException when called on successfully authorized token")
        void shouldThrowExceptionForSuccessfullyAuthorizedToken() {
            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.FULLY_VERIFIED)
                    .accessTokenContent(createTestToken())
                    .build();

            var exception = assertThrows(IllegalStateException.class, result::createErrorResponse);

            assertTrue(exception.getMessage().contains("Cannot create error response for successfully authorized token"));
            assertTrue(exception.getMessage().contains("status=" + BearerTokenStatus.FULLY_VERIFIED));
        }

        @Test
        @DisplayName("should delegate to BearerTokenResponseFactory for failed authorization")
        void shouldDelegateToResponseFactoryForFailedAuthorization() {
            var result = BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(Set.of("read"))
                    .requiredRoles(Set.of())
                    .requiredGroups(Set.of())
                    .build();

            var response = result.createErrorResponse();

            assertNotNull(response);
            // Detailed response testing is covered by BearerTokenResponseFactoryTest
        }
    }

    private AccessTokenContent createTestToken() {
        var holder = new TestTokenHolder(TokenType.ACCESS_TOKEN,
                ClaimControlParameter.defaultForTokenType(TokenType.ACCESS_TOKEN));
        return holder.asAccessTokenContent();
    }

    private BearerTokenResult createResultWithStatus(BearerTokenStatus status) {
        return switch (status) {
            case FULLY_VERIFIED -> BearerTokenResult.builder()
                    .status(BearerTokenStatus.FULLY_VERIFIED)
                    .accessTokenContent(createTestToken())
                    .build();
            case NO_TOKEN_GIVEN -> BearerTokenResult.noTokenGiven(Set.of(), Set.of(), Set.of());
            case PARSING_ERROR -> BearerTokenResult.parsingError(
                    new TokenValidationException(EventType.INVALID_JWT_FORMAT, "test"), Set.of(), Set.of(), Set.of());
            case CONSTRAINT_VIOLATION -> BearerTokenResult.builder()
                    .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                    .requiredScopes(Set.of())
                    .requiredRoles(Set.of())
                    .requiredGroups(Set.of())
                    .build();
            case INVALID_REQUEST -> BearerTokenResult.invalidRequest("Invalid token format", Set.of(), Set.of(), Set.of());
        };
    }
}