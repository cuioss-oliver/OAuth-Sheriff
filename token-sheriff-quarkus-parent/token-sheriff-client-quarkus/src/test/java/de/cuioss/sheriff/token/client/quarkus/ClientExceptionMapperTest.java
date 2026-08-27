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
package de.cuioss.sheriff.token.client.quarkus;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Problem+json rendering + no-leak tests for {@link ClientExceptionMapper} ({@code CLIENT-20},
 * {@code T-LEAK}) — deliverable 10.
 * <p>
 * The rendered document is asserted through the mapper's pure rendering helpers, so the invariants are
 * verified without bootstrapping a JAX-RS runtime.
 */
@DisplayName("ClientExceptionMapper problem+json edge")
class ClientExceptionMapperTest {

    @Test
    @DisplayName("Should render a 502 application/problem+json document for an upstream IdP failure")
    void shouldRenderProblemDocument() {
        String document = ClientExceptionMapper.problemJson();

        assertAll("problem document",
                () -> assertEquals(502, ClientExceptionMapper.status(), "an upstream IdP failure maps to 502 Bad Gateway"),
                () -> assertEquals("application/problem+json", ClientExceptionMapper.PROBLEM_JSON,
                        "the RFC 9457 media type is exposed"),
                () -> assertTrue(document.contains("\"status\":502"), "the document carries the status"),
                () -> assertTrue(document.contains("\"type\":\"" + ClientExceptionMapper.TYPE_BASE
                        + "idp-communication\""), "the document carries a stable problem type"),
                () -> assertTrue(document.contains("\"title\":"), "the document carries a title"),
                () -> assertTrue(document.contains("\"detail\":"), "the document carries a detail"));
    }

    @Test
    @DisplayName("Should render a constant document that cannot leak any internal detail")
    void shouldNotLeakInternalDetail() {
        String document = ClientExceptionMapper.problemJson();

        assertAll("no leak",
                () -> assertFalse(document.contains("jdbc"), "no internal identifier may appear"),
                () -> assertFalse(document.contains("timed out"), "no raw exception phrasing may appear"),
                () -> assertFalse(document.contains(".cluster.local"), "no internal host may appear"),
                () -> assertFalse(document.toLowerCase().contains("exception"), "no exception detail may appear"));
    }
}
