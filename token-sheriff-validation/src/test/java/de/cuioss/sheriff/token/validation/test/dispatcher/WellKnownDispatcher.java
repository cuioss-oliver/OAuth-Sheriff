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

import static jakarta.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static jakarta.servlet.http.HttpServletResponse.SC_OK;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Handles the resolving of OpenID Connect discovery document from the mocked server.
 * This dispatcher serves the .well-known/openid-configuration endpoint.
 */
@SuppressWarnings("UnusedReturnValue")
public class WellKnownDispatcher implements ModuleDispatcherElement {

    /**
     * "/.well-known/openid-configuration"
     */
    public static final String LOCAL_PATH = "/.well-known/openid-configuration";

    @Getter
    @Setter
    private int callCounter = 0;
    private ResponseStrategy responseStrategy = ResponseStrategy.DEFAULT;

    public WellKnownDispatcher() {
        // No initialization needed
    }

    /**
     * Convenience method to set the response strategy to return an error.
     *
     * @return this instance for method chaining
     */
    public WellKnownDispatcher returnError() {
        this.responseStrategy = ResponseStrategy.ERROR;
        return this;
    }

    /**
     * Convenience method to set the response strategy to return invalid JSON.
     *
     * @return this instance for method chaining
     */
    public WellKnownDispatcher returnInvalidJson() {
        this.responseStrategy = ResponseStrategy.INVALID_JSON;
        return this;
    }

    /**
     * Convenience method to set the response strategy to return a document with missing issuer.
     *
     * @return this instance for method chaining
     */
    public WellKnownDispatcher returnMissingIssuer() {
        this.responseStrategy = ResponseStrategy.MISSING_ISSUER;
        return this;
    }

    /**
     * Convenience method to set the response strategy to return a document with missing jwks_uri.
     *
     * @return this instance for method chaining
     */
    public WellKnownDispatcher returnMissingJwksUri() {
        this.responseStrategy = ResponseStrategy.MISSING_JWKS_URI;
        return this;
    }

    /**
     * Convenience method to set the response strategy to return a document with invalid issuer.
     *
     * @return this instance for method chaining
     */
    public WellKnownDispatcher returnInvalidIssuer() {
        this.responseStrategy = ResponseStrategy.INVALID_ISSUER;
        return this;
    }

    /**
     * Convenience method to set the response strategy to return a document with only required fields.
     *
     * @return this instance for method chaining
     */
    public WellKnownDispatcher returnOnlyRequiredFields() {
        this.responseStrategy = ResponseStrategy.ONLY_REQUIRED_FIELDS;
        return this;
    }

    /**
     * Convenience method to reset the response strategy to the default.
     *
     * @return this instance for method chaining
     */
    public WellKnownDispatcher returnDefault() {
        this.responseStrategy = ResponseStrategy.DEFAULT;
        return this;
    }

    /**
     * Determines the issuer URL based on the request.
     * 
     * @param request the HTTP request
     * @return the issuer URL to use in the response
     */
    private String determineIssuerUrl(RecordedRequest request) {
        // Extract the base URL from the request
        assert request.getUrl() != null;
        String requestUrl = request.getUrl().toString();
        // Remove the path part to get the base URL
        return requestUrl.substring(0, requestUrl.indexOf(LOCAL_PATH));
    }

    /**
     * Determines the JWKS URL based on the request.
     * 
     * @param request the HTTP request
     * @return the JWKS URL to use in the response
     */
    private String determineJwksUrl(RecordedRequest request) {
        // Extract the base URL from the request
        assert request.getUrl() != null;
        String requestUrl = request.getUrl().toString();
        // Remove the path part to get the base URL
        String baseUrl = requestUrl.substring(0, requestUrl.indexOf(LOCAL_PATH));
        return baseUrl + "/oidc/jwks.json";
    }

    @Override
    public Optional<MockResponse> handleGet(@NonNull RecordedRequest request) {
        callCounter++;

        // Determine the issuer and JWKS URLs dynamically from the request
        String dynamicIssuerUrl = determineIssuerUrl(request);
        String dynamicJwksUrl = determineJwksUrl(request);

        return switch (responseStrategy) {
            case ERROR -> Optional.of(new MockResponse(SC_INTERNAL_SERVER_ERROR, Headers.of(), ""));
            case INVALID_JSON -> Optional.of(new MockResponse(
                    SC_OK,
                    Headers.of("Content-Type", "application/json"),
                    "{ invalid json }"));
            case MISSING_ISSUER -> Optional.of(new MockResponse(
                    SC_OK,
                    Headers.of("Content-Type", "application/json"),
                    createWellKnownResponseWithoutIssuer(dynamicIssuerUrl, dynamicJwksUrl)));
            case MISSING_JWKS_URI -> Optional.of(new MockResponse(
                    SC_OK,
                    Headers.of("Content-Type", "application/json"),
                    createWellKnownResponseWithoutJwksUri(dynamicIssuerUrl)));
            case INVALID_ISSUER -> Optional.of(new MockResponse(
                    SC_OK,
                    Headers.of("Content-Type", "application/json"),
                    createWellKnownResponseWithInvalidIssuer(dynamicJwksUrl, dynamicIssuerUrl)));
            case ONLY_REQUIRED_FIELDS -> Optional.of(new MockResponse(
                    SC_OK,
                    Headers.of("Content-Type", "application/json"),
                    createWellKnownResponseWithOnlyRequiredFields(dynamicIssuerUrl, dynamicJwksUrl)));
            default -> Optional.of(new MockResponse(
                    SC_OK,
                    Headers.of("Content-Type", "application/json"),
                    createDefaultWellKnownResponse(dynamicIssuerUrl, dynamicJwksUrl)));
        };
    }

    /**
     * Creates a default well-known response with the given issuer and JWKS URLs.
     *
     * @param issuerUrl the issuer URL to use in the response
     * @param jwksUrl the JWKS URL to use in the response
     * @return the well-known response JSON
     */
    private String createDefaultWellKnownResponse(String issuerUrl, String jwksUrl) {
        return "{\n" +
                "  \"issuer\": \"" + issuerUrl + "\",\n" +
                "  \"authorization_endpoint\": \"" + issuerUrl + "/protocol/openid-connect/auth\",\n" +
                "  \"token_endpoint\": \"" + issuerUrl + "/protocol/openid-connect/token\",\n" +
                "  \"userinfo_endpoint\": \"" + issuerUrl + "/protocol/openid-connect/userinfo\",\n" +
                "  \"jwks_uri\": \"" + jwksUrl + "\",\n" +
                "  \"response_types_supported\": [\"code\", \"id_token\", \"token id_token\"],\n" +
                "  \"subject_types_supported\": [\"public\"],\n" +
                "  \"id_token_signing_alg_values_supported\": [\"RS256\"]\n" +
                "}";
    }

    /**
     * Creates a well-known response without the issuer field.
     *
     * @param issuerUrl the issuer URL to use in the response
     * @param jwksUrl the JWKS URL to use in the response
     * @return the well-known response JSON without issuer
     */
    private String createWellKnownResponseWithoutIssuer(String issuerUrl, String jwksUrl) {
        return "{\n" +
                "  \"authorization_endpoint\": \"" + issuerUrl + "/protocol/openid-connect/auth\",\n" +
                "  \"token_endpoint\": \"" + issuerUrl + "/protocol/openid-connect/token\",\n" +
                "  \"userinfo_endpoint\": \"" + issuerUrl + "/protocol/openid-connect/userinfo\",\n" +
                "  \"jwks_uri\": \"" + jwksUrl + "\",\n" +
                "  \"response_types_supported\": [\"code\", \"id_token\", \"token id_token\"],\n" +
                "  \"subject_types_supported\": [\"public\"],\n" +
                "  \"id_token_signing_alg_values_supported\": [\"RS256\"]\n" +
                "}";
    }

    /**
     * Creates a well-known response without the jwks_uri field.
     *
     * @param issuerUrl the issuer URL to use in the response
     * @return the well-known response JSON without jwks_uri
     */
    private String createWellKnownResponseWithoutJwksUri(String issuerUrl) {
        return "{\n" +
                "  \"issuer\": \"" + issuerUrl + "\",\n" +
                "  \"authorization_endpoint\": \"" + issuerUrl + "/protocol/openid-connect/auth\",\n" +
                "  \"token_endpoint\": \"" + issuerUrl + "/protocol/openid-connect/token\",\n" +
                "  \"userinfo_endpoint\": \"" + issuerUrl + "/protocol/openid-connect/userinfo\",\n" +
                "  \"response_types_supported\": [\"code\", \"id_token\", \"token id_token\"],\n" +
                "  \"subject_types_supported\": [\"public\"],\n" +
                "  \"id_token_signing_alg_values_supported\": [\"RS256\"]\n" +
                "}";
    }

    /**
     * Creates a well-known response with an invalid issuer.
     * Uses a modified version of the dynamic issuer URL to ensure it's invalid.
     *
     * @param jwksUrl the JWKS URL to use in the response
     * @param issuerUrl the issuer URL to use for endpoints
     * @return the well-known response JSON with invalid issuer
     */
    private String createWellKnownResponseWithInvalidIssuer(String jwksUrl, String issuerUrl) {
        // Create an invalid issuer by appending "-invalid" to the host part of the URL
        String invalidIssuerUrl = issuerUrl.replaceFirst("://", "://invalid-");

        return "{\n" +
                "  \"issuer\": \"" + invalidIssuerUrl + "\",\n" +
                "  \"authorization_endpoint\": \"" + issuerUrl + "/protocol/openid-connect/auth\",\n" +
                "  \"token_endpoint\": \"" + issuerUrl + "/protocol/openid-connect/token\",\n" +
                "  \"userinfo_endpoint\": \"" + issuerUrl + "/protocol/openid-connect/userinfo\",\n" +
                "  \"jwks_uri\": \"" + jwksUrl + "\",\n" +
                "  \"response_types_supported\": [\"code\", \"id_token\", \"token id_token\"],\n" +
                "  \"subject_types_supported\": [\"public\"],\n" +
                "  \"id_token_signing_alg_values_supported\": [\"RS256\"]\n" +
                "}";
    }

    /**
     * Creates a well-known response with only required fields (issuer and jwks_uri).
     *
     * @param issuerUrl the issuer URL to use in the response
     * @param jwksUrl the JWKS URL to use in the response
     * @return the well-known response JSON with only required fields
     */
    private String createWellKnownResponseWithOnlyRequiredFields(String issuerUrl, String jwksUrl) {
        return "{\n" +
                "  \"issuer\": \"" + issuerUrl + "\",\n" +
                "  \"jwks_uri\": \"" + jwksUrl + "\"\n" +
                "}";
    }

    @Override
    public String getBaseUrl() {
        return LOCAL_PATH;
    }

    @Override
    public @NonNull Set<HttpMethodMapper> supportedMethods() {
        return Set.of(HttpMethodMapper.GET, HttpMethodMapper.HEAD);
    }

    /**
     * Handles HEAD requests to the well-known endpoint.
     * Returns the same headers as GET but with no body.
     *
     * @param request the HTTP request
     * @return the HTTP response
     */
    @Override
    public Optional<MockResponse> handleHead(@NonNull RecordedRequest request) {
        callCounter++;

        // For HEAD requests, we return the same headers as GET but with no body
        return switch (responseStrategy) {
            case ERROR -> Optional.of(new MockResponse(SC_INTERNAL_SERVER_ERROR, Headers.of(), ""));
            default -> Optional.of(new MockResponse(
                    SC_OK,
                    Headers.of("Content-Type", "application/json"),
                    ""));
        };
    }

    /**
     * Verifies whether this endpoint was called the given times
     *
     * @param expected count of calls
     */
    public void assertCallsAnswered(int expected) {
        assertEquals(expected, callCounter);
    }

    /**
     * Enum representing the different response strategies for the well-known endpoint.
     */
    public enum ResponseStrategy {
        /**
         * Returns a normal well-known response.
         */
        DEFAULT,

        /**
         * Returns an HTTP 500 error response.
         */
        ERROR,

        /**
         * Returns invalid JSON content.
         */
        INVALID_JSON,

        /**
         * Returns a well-known document without the issuer field.
         */
        MISSING_ISSUER,

        /**
         * Returns a well-known document without the jwks_uri field.
         */
        MISSING_JWKS_URI,

        /**
         * Returns a well-known document with an invalid issuer.
         */
        INVALID_ISSUER,

        /**
         * Returns a well-known document with only required fields (issuer and jwks_uri).
         */
        ONLY_REQUIRED_FIELDS
    }
}
