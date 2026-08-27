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
package de.cuioss.sheriff.token.quarkus.interceptor;

import de.cuioss.sheriff.token.quarkus.annotation.BearerAuth;
import de.cuioss.sheriff.token.quarkus.producer.BearerTokenProducer;
import de.cuioss.sheriff.token.quarkus.producer.BearerTokenResult;
import de.cuioss.sheriff.token.quarkus.producer.BearerTokenStatus;
import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.ClaimControlParameter;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import jakarta.interceptor.InvocationContext;
import jakarta.ws.rs.WebApplicationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.easymock.EasyMock.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link BearerTokenInterceptor}.
 */
@EnableTestLogger
class BearerTokenInterceptorTest {

    private BearerTokenInterceptor interceptor;
    private BearerTokenProducer bearerTokenProducer;
    private InvocationContext invocationContext;

    private final TestResource testResource = new TestResource();

    @BeforeEach
    void setUp() {
        bearerTokenProducer = createMock(BearerTokenProducer.class);
        invocationContext = createMock(InvocationContext.class);
        interceptor = new BearerTokenInterceptor(bearerTokenProducer);
    }

    @Test
    @DisplayName("Should proceed when validation succeeds")
    void shouldProceedWhenValidationSucceeds() throws Exception {
        TestTokenHolder tokenHolder = createValidToken();

        expect(invocationContext.getMethod()).andReturn(TestResource.class.getMethod("methodWithScopes"));
        expect(invocationContext.getTarget()).andReturn(testResource);
        expect(bearerTokenProducer.getBearerTokenResult(Set.of("read"), Set.of(), Set.of()))
                .andReturn(BearerTokenResult.builder()
                        .status(BearerTokenStatus.FULLY_VERIFIED)
                        .accessTokenContent(tokenHolder.asAccessTokenContent())
                        .build());
        expect(invocationContext.proceed()).andReturn("success");
        replay(invocationContext, bearerTokenProducer);

        Object result = interceptor.validateBearerToken(invocationContext);

        assertEquals("success", result);
        verify(invocationContext, bearerTokenProducer);
    }

    @Test
    @DisplayName("Should throw WebApplicationException when validation fails")
    void shouldThrowWebApplicationExceptionWhenValidationFails() throws Exception {
        expect(invocationContext.getMethod()).andReturn(TestResource.class.getMethod("methodWithScopes"));
        expect(invocationContext.getTarget()).andReturn(testResource);
        expect(bearerTokenProducer.getBearerTokenResult(Set.of("read"), Set.of(), Set.of()))
                .andReturn(BearerTokenResult.noTokenGiven(Set.of("read"), Set.of(), Set.of()));
        replay(invocationContext, bearerTokenProducer);

        WebApplicationException exception = assertThrows(WebApplicationException.class,
                () -> interceptor.validateBearerToken(invocationContext));

        assertEquals(401, exception.getResponse().getStatus());
        verify(invocationContext, bearerTokenProducer);
    }

    @Test
    @DisplayName("Should extract multiple scopes correctly")
    void shouldExtractMultipleScopesCorrectly() throws Exception {
        TestTokenHolder tokenHolder = createValidToken();

        expect(invocationContext.getMethod()).andReturn(TestResource.class.getMethod("methodWithMultipleScopes"));
        expect(invocationContext.getTarget()).andReturn(testResource);
        expect(bearerTokenProducer.getBearerTokenResult(Set.of("read", "write", "admin"), Set.of(), Set.of()))
                .andReturn(BearerTokenResult.builder()
                        .status(BearerTokenStatus.FULLY_VERIFIED)
                        .accessTokenContent(tokenHolder.asAccessTokenContent())
                        .build());
        expect(invocationContext.proceed()).andReturn("success");
        replay(invocationContext, bearerTokenProducer);

        interceptor.validateBearerToken(invocationContext);

        verify(bearerTokenProducer);
    }

    @Test
    @DisplayName("Should extract multiple roles correctly")
    void shouldExtractMultipleRolesCorrectly() throws Exception {
        TestTokenHolder tokenHolder = createValidToken();

        expect(invocationContext.getMethod()).andReturn(TestResource.class.getMethod("methodWithRoles"));
        expect(invocationContext.getTarget()).andReturn(testResource);
        expect(bearerTokenProducer.getBearerTokenResult(Set.of(), Set.of("user", "admin"), Set.of()))
                .andReturn(BearerTokenResult.builder()
                        .status(BearerTokenStatus.FULLY_VERIFIED)
                        .accessTokenContent(tokenHolder.asAccessTokenContent())
                        .build());
        expect(invocationContext.proceed()).andReturn("success");
        replay(invocationContext, bearerTokenProducer);

        interceptor.validateBearerToken(invocationContext);

        verify(bearerTokenProducer);
    }

    @Test
    @DisplayName("Should extract multiple groups correctly")
    void shouldExtractMultipleGroupsCorrectly() throws Exception {
        TestTokenHolder tokenHolder = createValidToken();

        expect(invocationContext.getMethod()).andReturn(TestResource.class.getMethod("methodWithGroups"));
        expect(invocationContext.getTarget()).andReturn(testResource);
        expect(bearerTokenProducer.getBearerTokenResult(Set.of(), Set.of(), Set.of("developers", "managers")))
                .andReturn(BearerTokenResult.builder()
                        .status(BearerTokenStatus.FULLY_VERIFIED)
                        .accessTokenContent(tokenHolder.asAccessTokenContent())
                        .build());
        expect(invocationContext.proceed()).andReturn("success");
        replay(invocationContext, bearerTokenProducer);

        interceptor.validateBearerToken(invocationContext);

        verify(bearerTokenProducer);
    }

    @Test
    @DisplayName("Should handle all requirements combined")
    void shouldHandleAllRequirementsCombined() throws Exception {
        TestTokenHolder tokenHolder = createValidToken();

        expect(invocationContext.getMethod()).andReturn(TestResource.class.getMethod("methodWithAllRequirements"));
        expect(invocationContext.getTarget()).andReturn(testResource);
        expect(bearerTokenProducer.getBearerTokenResult(
                Set.of("read", "write"),
                Set.of("user"),
                Set.of("team-a")))
                .andReturn(BearerTokenResult.builder()
                        .status(BearerTokenStatus.FULLY_VERIFIED)
                        .accessTokenContent(tokenHolder.asAccessTokenContent())
                        .build());
        expect(invocationContext.proceed()).andReturn("success");
        replay(invocationContext, bearerTokenProducer);

        interceptor.validateBearerToken(invocationContext);

        verify(bearerTokenProducer);
    }

    @Test
    @DisplayName("Should handle empty annotation (no requirements)")
    void shouldHandleEmptyAnnotation() throws Exception {
        TestTokenHolder tokenHolder = createValidToken();

        expect(invocationContext.getMethod()).andReturn(TestResource.class.getMethod("methodWithEmptyAnnotation"));
        expect(invocationContext.getTarget()).andReturn(testResource);
        expect(bearerTokenProducer.getBearerTokenResult(Set.of(), Set.of(), Set.of()))
                .andReturn(BearerTokenResult.builder()
                        .status(BearerTokenStatus.FULLY_VERIFIED)
                        .accessTokenContent(tokenHolder.asAccessTokenContent())
                        .build());
        expect(invocationContext.proceed()).andReturn("success");
        replay(invocationContext, bearerTokenProducer);

        interceptor.validateBearerToken(invocationContext);

        verify(bearerTokenProducer);
    }

    @Test
    @DisplayName("Should throw IllegalStateException when annotation not found (fail closed)")
    void shouldThrowWhenAnnotationNotFound() throws Exception {
        expect(invocationContext.getMethod()).andReturn(TestResource.class.getMethod("methodWithoutAnnotation")).times(2);
        expect(invocationContext.getTarget()).andReturn(testResource);
        replay(invocationContext, bearerTokenProducer);

        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> interceptor.validateBearerToken(invocationContext));

        assertTrue(exception.getMessage().contains("@BearerAuth annotation not found"),
                "Exception message should mention missing annotation");
        verify(invocationContext);
    }

    @Test
    @DisplayName("Should extract annotation from class level")
    void shouldExtractAnnotationFromClassLevel() throws Exception {
        TestTokenHolder tokenHolder = createValidToken();
        TestResourceClassLevel resource = new TestResourceClassLevel();

        expect(invocationContext.getMethod()).andReturn(TestResourceClassLevel.class.getMethod("methodWithoutAnnotation"));
        expect(invocationContext.getTarget()).andReturn(resource);
        expect(bearerTokenProducer.getBearerTokenResult(Set.of("class-scope"), Set.of(), Set.of()))
                .andReturn(BearerTokenResult.builder()
                        .status(BearerTokenStatus.FULLY_VERIFIED)
                        .accessTokenContent(tokenHolder.asAccessTokenContent())
                        .build());
        expect(invocationContext.proceed()).andReturn("success");
        replay(invocationContext, bearerTokenProducer);

        interceptor.validateBearerToken(invocationContext);

        verify(bearerTokenProducer);
    }

    @Test
    @DisplayName("Should return status 401 for missing scopes")
    void shouldReturn401ForMissingScopes() throws Exception {
        expect(invocationContext.getMethod()).andReturn(TestResource.class.getMethod("methodWithScopes"));
        expect(invocationContext.getTarget()).andReturn(testResource);
        expect(bearerTokenProducer.getBearerTokenResult(Set.of("read"), Set.of(), Set.of()))
                .andReturn(BearerTokenResult.builder()
                        .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                        .requiredScopes(Set.of("read"))
                        .missingScopes(Set.of("read"))
                        .requiredRoles(Set.of())
                        .requiredGroups(Set.of())
                        .build());
        replay(invocationContext, bearerTokenProducer);

        WebApplicationException exception = assertThrows(WebApplicationException.class,
                () -> interceptor.validateBearerToken(invocationContext));

        assertEquals(401, exception.getResponse().getStatus());
        verify(invocationContext, bearerTokenProducer);
    }

    @Test
    @DisplayName("Should return status 403 for missing roles")
    void shouldReturn403ForMissingRoles() throws Exception {
        expect(invocationContext.getMethod()).andReturn(TestResource.class.getMethod("methodWithRoles"));
        expect(invocationContext.getTarget()).andReturn(testResource);
        expect(bearerTokenProducer.getBearerTokenResult(Set.of(), Set.of("user", "admin"), Set.of()))
                .andReturn(BearerTokenResult.builder()
                        .status(BearerTokenStatus.CONSTRAINT_VIOLATION)
                        .requiredScopes(Set.of())
                        .requiredRoles(Set.of("user"))
                        .missingRoles(Set.of("user"))
                        .requiredGroups(Set.of())
                        .build());
        replay(invocationContext, bearerTokenProducer);

        WebApplicationException exception = assertThrows(WebApplicationException.class,
                () -> interceptor.validateBearerToken(invocationContext));

        assertEquals(403, exception.getResponse().getStatus());
        verify(invocationContext, bearerTokenProducer);
    }

    private TestTokenHolder createValidToken() {
        return new TestTokenHolder(TokenType.ACCESS_TOKEN,
                ClaimControlParameter.defaultForTokenType(TokenType.ACCESS_TOKEN));
    }

    public static class TestResource {
        @BearerAuth(requiredScopes = {"read"})
        public String methodWithScopes() {
            return "result";
        }

        @BearerAuth(requiredScopes = {"read", "write", "admin"})
        public String methodWithMultipleScopes() {
            return "result";
        }

        @BearerAuth(requiredRoles = {"user", "admin"})
        public String methodWithRoles() {
            return "result";
        }

        @BearerAuth(requiredGroups = {"developers", "managers"})
        public String methodWithGroups() {
            return "result";
        }

        @BearerAuth(requiredScopes = {"read", "write"}, requiredRoles = {"user"}, requiredGroups = {"team-a"})
        public String methodWithAllRequirements() {
            return "result";
        }

        @BearerAuth
        public String methodWithEmptyAnnotation() {
            return "result";
        }

        public String methodWithoutAnnotation() {
            return "result";
        }
    }

    @BearerAuth(requiredScopes = {"class-scope"})
    public static class TestResourceClassLevel {
        public String methodWithoutAnnotation() {
            return "result";
        }
    }
}
