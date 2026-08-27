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

import de.cuioss.sheriff.token.validation.test.InMemoryJWKSFactory;
import lombok.Getter;
import lombok.NonNull;
import mockwebserver3.MockResponse;
import mockwebserver3.RecordedRequest;
import okhttp3.Headers;

import java.util.Optional;

import static jakarta.servlet.http.HttpServletResponse.SC_NOT_MODIFIED;
import static jakarta.servlet.http.HttpServletResponse.SC_OK;

/**
 * Enhanced version of {@link JwksResolveDispatcher} that adds support for testing
 * HTTP 304 handling, content-based caching, and fallback mechanisms.
 */
@SuppressWarnings("UnusedReturnValue")
public class EnhancedJwksResolveDispatcher extends JwksResolveDispatcher {

    private static final String ETAG_VALUE = "\"test-etag-value\"";
    private ResponseStrategy responseStrategy = ResponseStrategy.DEFAULT;
    private String differentContentKeyId = null;

    @Getter
    private boolean ifNoneMatchHeaderPresent = false;

    /**
     * Sets the response strategy to return a 304 Not Modified response.
     *
     * @return this instance for method chaining
     */
    public EnhancedJwksResolveDispatcher returnNotModified() {
        this.responseStrategy = ResponseStrategy.NOT_MODIFIED;
        return this;
    }

    /**
     * Sets the response strategy to return the same content but with a different ETag.
     *
     * @return this instance for method chaining
     */
    public EnhancedJwksResolveDispatcher returnSameContent() {
        this.responseStrategy = ResponseStrategy.SAME_CONTENT;
        return this;
    }

    /**
     * Sets the response strategy to return different content with a new key ID.
     *
     * @param newKeyId the new key ID to use in the JWKS
     * @return this instance for method chaining
     */
    public EnhancedJwksResolveDispatcher returnDifferentContent(String newKeyId) {
        this.responseStrategy = ResponseStrategy.DIFFERENT_CONTENT;
        this.differentContentKeyId = newKeyId;
        return this;
    }

    /**
     * Sets the response strategy to simulate a connection failure.
     *
     * @return this instance for method chaining
     */
    public EnhancedJwksResolveDispatcher simulateConnectionFailure() {
        this.responseStrategy = ResponseStrategy.CONNECTION_FAILURE;
        return this;
    }

    /**
     * Configures the dispatcher to check for the If-None-Match header.
     *
     * @return this instance for method chaining
     */
    public EnhancedJwksResolveDispatcher expectIfNoneMatchHeader() {
        this.responseStrategy = ResponseStrategy.CHECK_IF_NONE_MATCH;
        return this;
    }

    /**
     * Returns whether the If-None-Match header was present in the last request.
     *
     * @return true if the If-None-Match header was present, false otherwise
     */
    public boolean wasIfNoneMatchHeaderPresent() {
        return ifNoneMatchHeaderPresent;
    }

    @Override
    public Optional<MockResponse> handleGet(@NonNull RecordedRequest request) {
        // Always increment call counter for all requests
        setCallCounter(getCallCounter() + 1);

        // Check for If-None-Match header if expected
        if (responseStrategy == ResponseStrategy.CHECK_IF_NONE_MATCH) {
            // Get headers from64EncodedContent request
            Headers headers = request.getHeaders();
            String ifNoneMatch = headers.get("If-None-Match");
            ifNoneMatchHeaderPresent = ifNoneMatch != null && !ifNoneMatch.isEmpty();
            // Return default response
            return createDefaultResponse();
        }

        // Handle other response strategies
        return switch (responseStrategy) {
            case NOT_MODIFIED -> Optional.of(new MockResponse(SC_NOT_MODIFIED, Headers.of("ETag", ETAG_VALUE), ""));
            case SAME_CONTENT -> createDefaultResponse();
            case DIFFERENT_CONTENT -> {
                if (differentContentKeyId != null) {
                    // Create JWKS with a different key ID
                    String differentContent = InMemoryJWKSFactory.createValidJwksWithKeyId(differentContentKeyId);
                    yield Optional.of(new MockResponse(SC_OK, Headers.of("Content-Type", "application/json", "ETag", "\"new-etag-value\""), differentContent));
                }
                yield createDefaultResponse();
            }
            case CONNECTION_FAILURE -> throw new IllegalStateException("Simulated connection failure");
            default ->
                // Use parent class behavior for other cases
                // Note: We don't call super.handleGet() because it would increment the counter again
                createDefaultResponse();
        };
    }

    private Optional<MockResponse> createDefaultResponse() {
        // Create a default response with ETag
        return Optional.of(new MockResponse(SC_OK, Headers.of("Content-Type", "application/json", "ETag", ETAG_VALUE), InMemoryJWKSFactory.createDefaultJwks()));
    }

    /**
     * Enum representing the enhanced response strategies.
     */
    private enum ResponseStrategy {
        DEFAULT, NOT_MODIFIED, SAME_CONTENT, DIFFERENT_CONTENT, CONNECTION_FAILURE, CHECK_IF_NONE_MATCH
    }
}
