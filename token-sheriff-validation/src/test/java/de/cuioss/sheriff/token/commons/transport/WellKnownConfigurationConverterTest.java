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
package de.cuioss.sheriff.token.commons.transport;

import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests WellKnownConfigurationConverter streaming size ceiling (H2)")
class WellKnownConfigurationConverterTest {

    private static final int MAX_CONTENT_SIZE = 64;

    private WellKnownConfigurationConverter newConverter() {
        return new WellKnownConfigurationConverter(
                ParserConfig.builder().build().getDslJson(),
                new SecurityEventCounter(),
                MAX_CONTENT_SIZE);
    }

    @Test
    @DisplayName("Should reject an over-limit body during streaming without full buffering")
    void shouldRejectOverLimitBodyDuringStreaming() {
        HttpResponse.BodyHandler<?> handler = newConverter().getBodyHandler();
        byte[] overLimit = "x".repeat(MAX_CONTENT_SIZE + 40).getBytes(StandardCharsets.UTF_8);

        var result = BoundedBodyHandlerTestSupport.drive(handler, overLimit, null);

        assertFalse(result.succeeded(), "Over-limit body must fail closed, not materialize");
        assertNotNull(result.failure());
        assertTrue(result.failure().getMessage().contains("exceeds maximum allowed size"),
                "Failure must name the size-ceiling breach, but was: " + result.failure().getMessage());
        assertTrue(result.cancelled(),
                "Subscription must be cancelled mid-stream — the over-limit body is not fully buffered");
    }

    @Test
    @DisplayName("Should reject an over-limit body via the Content-Length pre-check")
    void shouldRejectOverLimitBodyViaContentLengthPreCheck() {
        HttpResponse.BodyHandler<?> handler = newConverter().getBodyHandler();
        byte[] overLimit = "x".repeat(MAX_CONTENT_SIZE + 40).getBytes(StandardCharsets.UTF_8);

        var result = BoundedBodyHandlerTestSupport.drive(handler, overLimit, (long) overLimit.length);

        assertFalse(result.succeeded(), "A body advertising an over-limit Content-Length must be rejected");
        assertNotNull(result.failure());
        assertTrue(result.failure().getMessage().contains("exceeds maximum allowed size"),
                "Failure must name the size-ceiling breach, but was: " + result.failure().getMessage());
        assertTrue(result.cancelled(),
                "Content-Length pre-check must cancel the subscription — the over-limit body is never read, not drained");
    }

    @Test
    @DisplayName("Should accept an at-limit body")
    void shouldAcceptAtLimitBody() {
        HttpResponse.BodyHandler<?> handler = newConverter().getBodyHandler();
        String atLimit = "y".repeat(MAX_CONTENT_SIZE);
        byte[] body = atLimit.getBytes(StandardCharsets.UTF_8);

        var result = BoundedBodyHandlerTestSupport.drive(handler, body, (long) body.length);

        assertTrue(result.succeeded(), "An at-limit body must be accepted");
        assertEquals(atLimit, result.body());
        assertFalse(result.cancelled(), "An at-limit body must not trigger a streaming abort");
    }

    @Test
    @DisplayName("Should reject over-limit content in convert() as defense in depth")
    void shouldRejectOverLimitContentInConvertAsDefenseInDepth() {
        WellKnownConfigurationConverter converter = newConverter();
        String overLimit = "z".repeat(MAX_CONTENT_SIZE + 40);

        TransportException exception = assertThrows(TransportException.class,
                () -> converter.convert(overLimit),
                "convert() must fail closed with a typed exception for an over-limit body");
        assertTrue(exception.getMessage().contains("size exceeds maximum allowed size"),
                "Exception must name the size violation, but was: " + exception.getMessage());
    }

    @Test
    @DisplayName("Should expose a non-null bounded body handler")
    void shouldExposeBoundedBodyHandler() {
        assertNotNull(newConverter().getBodyHandler());
    }
}
