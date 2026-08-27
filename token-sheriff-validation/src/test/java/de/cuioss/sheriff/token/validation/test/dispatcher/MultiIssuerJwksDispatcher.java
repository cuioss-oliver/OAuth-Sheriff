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
package de.cuioss.sheriff.token.validation.test.dispatcher;

import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.test.mockwebserver.dispatcher.HttpMethodMapper;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcherElement;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import mockwebserver3.MockResponse;
import mockwebserver3.RecordedRequest;
import okhttp3.Headers;

import java.util.Optional;
import java.util.Set;

import static jakarta.servlet.http.HttpServletResponse.SC_OK;

/**
 * Handles the resolving of JWKS files from multiple issuers.
 * <p>
 * This dispatcher supports multiple JWKS endpoints with different keys.
 */
public class MultiIssuerJwksDispatcher implements ModuleDispatcherElement {

    /**
     * Path for issuer 1.
     */
    public static final String ISSUER1_PATH = "/issuer1/jwks.json";

    /**
     * Path for issuer 2.
     */
    public static final String ISSUER2_PATH = "/issuer2/jwks.json";

    /**
     * Key ID for issuer 1.
     */
    public static final String ISSUER1_KID = "issuer1-kid";

    /**
     * Key ID for issuer 2.
     */
    public static final String ISSUER2_KID = "issuer2-kid";

    @Getter
    @Setter
    private int callCounter = 0;

    @Override
    public Optional<MockResponse> handleGet(@NonNull RecordedRequest request) {
        callCounter++;

        String path = request.getUrl() != null ? request.getUrl().encodedPath() : null;
        if (path == null) {
            return Optional.empty();
        }

        // Handle both exact paths and paths that contain the issuer paths
        // This is needed because the URIBuilder in the test is appending paths
        if (path.contains(ISSUER2_PATH)) {
            return Optional.of(createJwksResponse(ISSUER2_KID, InMemoryKeyMaterialHandler.Algorithm.RS384));
        } else if (path.contains(ISSUER1_PATH)) {
            return Optional.of(createJwksResponse(ISSUER1_KID, InMemoryKeyMaterialHandler.Algorithm.RS256));
        }

        return Optional.empty();
    }

    /**
     * Creates a JWKS response with the specified key ID and algorithm.
     *
     * @param keyId     the key ID
     * @param algorithm the algorithm
     * @return a MockResponse containing the JWKS
     */
    private MockResponse createJwksResponse(String keyId, InMemoryKeyMaterialHandler.Algorithm algorithm) {
        String jwks = InMemoryKeyMaterialHandler.createJwks(algorithm, keyId);
        return new MockResponse(SC_OK, Headers.of("Content-Type", "application/json"), jwks);
    }

    @Override
    public String getBaseUrl() {
        // Return an empty string to match all paths
        // This allows the CombinedDispatcher to properly route requests
        return "";
    }

    @Override
    public @NonNull Set<HttpMethodMapper> supportedMethods() {
        return Set.of(HttpMethodMapper.GET);
    }
}
