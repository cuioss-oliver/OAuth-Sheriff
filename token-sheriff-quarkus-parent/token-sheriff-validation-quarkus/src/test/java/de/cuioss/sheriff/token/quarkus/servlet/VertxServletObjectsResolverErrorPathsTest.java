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
package de.cuioss.sheriff.token.quarkus.servlet;

import de.cuioss.sheriff.token.quarkus.TokenSheriffQuarkusLogMessages;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerRequest;
import jakarta.enterprise.inject.Instance;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.easymock.EasyMock.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit tests for {@link VertxServletObjectsResolver} error paths.
 *
 * <p>Tests the defensive error handling when CDI context is unavailable or misconfigured.
 * These scenarios should not occur in properly configured applications but are tested for completeness.</p>
 *
 * @author Oliver Wolff
 */
@EnableTestLogger
@DisplayName("VertxServletObjectsResolver Error Path Tests")
class VertxServletObjectsResolverErrorPathsTest {

    private Instance<HttpServerRequest> vertxRequestInstance;
    private VertxServletObjectsResolver resolver;

    @BeforeEach
    void setUp() {
        vertxRequestInstance = createMock(Instance.class);
        resolver = new VertxServletObjectsResolver(vertxRequestInstance);
    }

    @Test
    @DisplayName("resolveHeaderMap should throw when CDI Instance is unsatisfied")
    void resolveHeaderMapShouldThrowWhenUnsatisfied() {
        expect(vertxRequestInstance.isUnsatisfied()).andReturn(true);
        replay(vertxRequestInstance);

        assertThrows(IllegalStateException.class, () -> resolver.resolveHeaderMap());
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR,
                TokenSheriffQuarkusLogMessages.ERROR.VERTX_REQUEST_CONTEXT_UNAVAILABLE.resolveIdentifierString());
        verify(vertxRequestInstance);
    }

    @Test
    @DisplayName("resolveHeaderMap should throw when HttpServerRequest is null")
    void resolveHeaderMapShouldThrowWhenNull() {
        expect(vertxRequestInstance.isUnsatisfied()).andReturn(false);
        expect(vertxRequestInstance.get()).andReturn(null);
        replay(vertxRequestInstance);

        assertThrows(IllegalStateException.class, () -> resolver.resolveHeaderMap());
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR,
                TokenSheriffQuarkusLogMessages.ERROR.VERTX_REQUEST_CONTEXT_UNAVAILABLE.resolveIdentifierString());
        verify(vertxRequestInstance);
    }

    @Test
    @DisplayName("resolveRequestUri should throw when CDI Instance is unsatisfied")
    void resolveRequestUriShouldThrowWhenUnsatisfied() {
        expect(vertxRequestInstance.isUnsatisfied()).andReturn(true);
        replay(vertxRequestInstance);

        assertThrows(IllegalStateException.class, () -> resolver.resolveRequestUri());
        verify(vertxRequestInstance);
    }

    @Test
    @DisplayName("resolveRequestUri should throw when HttpServerRequest is null")
    void resolveRequestUriShouldThrowWhenNull() {
        expect(vertxRequestInstance.isUnsatisfied()).andReturn(false);
        expect(vertxRequestInstance.get()).andReturn(null);
        replay(vertxRequestInstance);

        assertThrows(IllegalStateException.class, () -> resolver.resolveRequestUri());
        verify(vertxRequestInstance);
    }

    @Test
    @DisplayName("resolveRequestMethod should throw when CDI Instance is unsatisfied")
    void resolveRequestMethodShouldThrowWhenUnsatisfied() {
        expect(vertxRequestInstance.isUnsatisfied()).andReturn(true);
        replay(vertxRequestInstance);

        assertThrows(IllegalStateException.class, () -> resolver.resolveRequestMethod());
        verify(vertxRequestInstance);
    }

    @Test
    @DisplayName("resolveRequestMethod should throw when HttpServerRequest is null")
    void resolveRequestMethodShouldThrowWhenNull() {
        expect(vertxRequestInstance.isUnsatisfied()).andReturn(false);
        expect(vertxRequestInstance.get()).andReturn(null);
        replay(vertxRequestInstance);

        assertThrows(IllegalStateException.class, () -> resolver.resolveRequestMethod());
        verify(vertxRequestInstance);
    }

    @Test
    @DisplayName("resolveRequestUri should return absolute URI from Vertx request")
    void resolveRequestUriShouldReturnAbsoluteUri() {
        HttpServerRequest mockRequest = createMock(HttpServerRequest.class);
        expect(vertxRequestInstance.isUnsatisfied()).andReturn(false);
        expect(vertxRequestInstance.get()).andReturn(mockRequest);
        expect(mockRequest.absoluteURI()).andReturn("https://localhost:8443/jwt/validate");
        replay(vertxRequestInstance, mockRequest);

        assertEquals("https://localhost:8443/jwt/validate", resolver.resolveRequestUri());
        verify(vertxRequestInstance, mockRequest);
    }

    @Test
    @DisplayName("resolveRequestMethod should return HTTP method from Vertx request")
    void resolveRequestMethodShouldReturnMethod() {
        HttpServerRequest mockRequest = createMock(HttpServerRequest.class);
        expect(vertxRequestInstance.isUnsatisfied()).andReturn(false);
        expect(vertxRequestInstance.get()).andReturn(mockRequest);
        expect(mockRequest.method()).andReturn(HttpMethod.POST);
        replay(vertxRequestInstance, mockRequest);

        assertEquals("POST", resolver.resolveRequestMethod());
        verify(vertxRequestInstance, mockRequest);
    }
}
