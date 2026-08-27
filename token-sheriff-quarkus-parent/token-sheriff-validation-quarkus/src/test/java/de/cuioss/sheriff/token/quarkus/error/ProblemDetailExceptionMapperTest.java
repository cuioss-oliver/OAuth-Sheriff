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
package de.cuioss.sheriff.token.quarkus.error;

import de.cuioss.sheriff.token.commons.error.TransportException;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter.EventType;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ProblemDetailExceptionMapper — RFC 9457 rendering at the edge")
class ProblemDetailExceptionMapperTest {

    private final ProblemDetailExceptionMapper mapper = new ProblemDetailExceptionMapper();

    @Test
    @DisplayName("Token validation failure maps to 401 problem+json without leaking detail")
    void mapsTokenValidationFailure() {
        var response = mapper.toResponse(
                new TokenValidationException(EventType.TOKEN_EXPIRED, "exp=1700000000 sub=secret-subject"));

        assertEquals(401, response.getStatus());
        assertEquals(ProblemDetailExceptionMapper.PROBLEM_JSON, response.getMediaType().toString());
        String body = (String) response.getEntity();
        assertTrue(body.contains("\"status\":401"));
        assertTrue(body.contains("token-invalid"));
        // COMMONS-12 / T-LEAK: the internal exception message must not leak.
        assertFalse(body.contains("secret-subject"));
        assertFalse(body.contains("1700000000"));
    }

    @Test
    @DisplayName("Transport failure maps to 502 problem+json")
    void mapsTransportFailure() {
        var response = mapper.toResponse(new TransportException("connect timeout to https://internal.host"));

        assertEquals(502, response.getStatus());
        assertEquals(ProblemDetailExceptionMapper.PROBLEM_JSON, response.getMediaType().toString());
        String body = (String) response.getEntity();
        assertTrue(body.contains("idp-communication"));
        assertFalse(body.contains("internal.host"));
    }

    @Test
    @DisplayName("Response carries the RFC 9457 problem+json content type")
    void usesProblemJsonMediaType() {
        var response = mapper.toResponse(new TransportException("boom"));
        assertEquals("application", response.getMediaType().getType());
        assertEquals("problem+json", response.getMediaType().getSubtype());
        assertEquals(Response.Status.BAD_GATEWAY.getStatusCode(), response.getStatus());
    }
}
