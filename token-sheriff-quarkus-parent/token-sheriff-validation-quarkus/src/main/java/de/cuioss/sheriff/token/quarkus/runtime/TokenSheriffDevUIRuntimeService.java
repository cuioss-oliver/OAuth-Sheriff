/*
 * Copyright © 2022 CUI-OpenSource-Software (info@cuioss.de)
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
package de.cuioss.sheriff.token.quarkus.runtime;

import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.quarkus.observability.ObservedValidatorResolver;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.domain.token.TokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonException;

import java.util.*;

/**
 * Runtime JSON-RPC service for Token-Sheriff DevUI.
 * <p>
 * Provides read-only status information and token validation for the DevUI
 * components. All methods return {@link Map} structures serialized as JSON-RPC
 * responses over WebSocket.
 * </p>
 *
 * @since 1.0
 */
@ApplicationScoped
public class TokenSheriffDevUIRuntimeService {

    // String constants for commonly used literals
    private static final String MESSAGE = "message";
    private static final String VALID = "valid";
    private static final String ERROR = "error";
    private static final String TOKEN_TYPE = "tokenType";
    private static final String CLAIMS = "claims";
    private static final String ISSUER = "issuer";
    private static final String HEALTH_STATUS = "healthStatus";
    private static final String STATUS = "status";
    private static final String DETAILS = "details";
    private static final String NOT_CONFIGURED = "NOT_CONFIGURED";
    private static final String UNAVAILABLE_EXTERNAL_VALIDATOR = "unavailable (external validator)";
    private static final String UNAVAILABLE_NOT_CONFIGURED = "unavailable (not configured)";

    private final ObservedValidatorResolver resolver;

    /**
     * Constructor for dependency injection.
     *
     * @param resolver resolves the validator, issuer configurations and parser configuration
     *                 actually in use — which may belong to an externally-produced validator
     */
    @Inject
    public TokenSheriffDevUIRuntimeService(ObservedValidatorResolver resolver) {
        this.resolver = resolver;
    }

    /**
     * Get runtime JWT validation status.
     *
     * @return A map containing runtime validation status information
     */

    public Map<String, Object> getValidationStatus() {
        boolean validatorPresent = resolver.observedValidator().isPresent();
        Map<String, Object> status = new HashMap<>();
        status.put("enabled", true);
        status.put("validatorPresent", validatorPresent);
        status.put(STATUS, validatorPresent ? "ACTIVE" : NOT_CONFIGURED);
        status.put("statusMessage", validatorPresent
                ? "JWT validation is active and ready"
                : "No TokenValidator is configured");
        return status;
    }

    /**
     * Get runtime JWKS endpoint status.
     *
     * @return A map containing runtime JWKS status information
     */
   
    public Map<String, Object> getJwksStatus() {
        Map<String, Object> jwksInfo = new HashMap<>();

        List<IssuerConfig> issuerConfigs = resolver.observedIssuerConfigs();
        jwksInfo.put(STATUS, issuerConfigs.isEmpty() ? resolver.outcome().name() : "CONFIGURED");

        // Build issuers array with details for each configured issuer
        List<Map<String, Object>> issuers = new ArrayList<>();
        for (IssuerConfig ic : issuerConfigs) {
            Map<String, Object> issuer = new HashMap<>();
            String identifier = ic.getIssuerIdentifier();
            issuer.put("name", identifier);
            issuer.put("issuerUri", identifier);
            issuer.put("jwksUri", ic.getJwksLoader() != null ? "configured" : "not configured");
            issuer.put("loaderStatus", ic.getLoaderStatus().toString());
            issuer.put("lastRefresh", "N/A");
            issuers.add(issuer);
        }
        jwksInfo.put("issuers", issuers);

        return jwksInfo;
    }

    /**
     * Get runtime configuration information.
     *
     * @return A map containing runtime configuration information
     */
   
    public Map<String, Object> getConfiguration() {
        Map<String, Object> configMap = new HashMap<>();

        configMap.put("enabled", true);
        configMap.put("logLevel", "INFO");

        List<IssuerConfig> issuerConfigs = resolver.observedIssuerConfigs();
        ParserConfig parserConfig = resolver.observedParserConfig().orElse(null);
        String unavailableMarker = resolver.outcome() == ObservedValidatorResolver.Outcome.EXTERNAL_VALIDATOR
                ? UNAVAILABLE_EXTERNAL_VALIDATOR
                : UNAVAILABLE_NOT_CONFIGURED;

        // Parser configuration section — values from actual runtime config. Both this section and
        // httpJwksLoader.sizeLimit below are parserConfig-derived, so they carry the same
        // unavailability marker when no parser configuration is observable.
        Map<String, Object> parser = new HashMap<>();
        if (parserConfig == null) {
            parser.put(STATUS, unavailableMarker);
        } else {
            parser.put("maxTokenSize", parserConfig.getMaxTokenSize());
            parser.put("maxPayloadSize", parserConfig.getMaxPayloadSize());
            parser.put("maxStringLength", parserConfig.getMaxStringLength());
            // Clock skew is per-issuer; show the first issuer's value when one is observable
            if (!issuerConfigs.isEmpty()) {
                parser.put("clockSkewSeconds", issuerConfigs.getFirst().getClockSkewSeconds());
            }
        }
        configMap.put("parser", parser);

        // HTTP JWKS loader configuration section — approximate defaults from HttpHandler (external library)
        Map<String, Object> httpJwksLoader = new HashMap<>();
        httpJwksLoader.put("connectTimeoutSeconds", "per-issuer (default: ~10s, from HttpHandler)");
        httpJwksLoader.put("readTimeoutSeconds", "per-issuer (default: ~10s, from HttpHandler)");
        httpJwksLoader.put("sizeLimit", parserConfig == null ? unavailableMarker : parserConfig.getMaxTokenSize());
        configMap.put("httpJwksLoader", httpJwksLoader);

        // Issuers configuration section
        Map<String, Object> issuersMap = new LinkedHashMap<>();
        for (IssuerConfig ic : issuerConfigs) {
            String identifier = ic.getIssuerIdentifier();
            String name = identifier;
            Map<String, Object> issuerDetail = new HashMap<>();
            issuerDetail.put("issuerUri", identifier);
            issuerDetail.put("jwksUri", ic.getJwksLoader() != null ? "configured" : null);
            issuerDetail.put("audience", ic.getExpectedAudience().isEmpty() ? null
                    : String.join(", ", ic.getExpectedAudience()));
            issuerDetail.put("clockSkewSeconds", ic.getClockSkewSeconds());
            issuerDetail.put("expectedTokenType", ic.getExpectedTokenType());
            issuerDetail.put("claimSubOptional", ic.isClaimSubOptional());
            issuerDetail.put("dpopEnabled", ic.getDpopConfig() != null);
            issuersMap.put(name, issuerDetail);
        }
        configMap.put("issuers", issuersMap);

        return configMap;
    }

    /**
     * Validate a JWT access token using the runtime validator.
     * Only validates access tokens, not ID tokens or refresh tokens.
     *
     * @param token The JWT access token to validate
     * @return A map containing validation result
     */
   
    public Map<String, Object> validateToken(String token) {
        Map<String, Object> result = new HashMap<>();
        // Set default state - token is invalid until proven valid
        result.put(VALID, false);

        if (token == null || token.trim().isEmpty()) {
            result.put(ERROR, "Token is empty or null");
            return result;
        }

        TokenValidator tokenValidator = resolver.observedValidator().orElse(null);
        if (tokenValidator == null) {
            result.put(ERROR, "No validator configured");
            result.put(DETAILS, "No TokenValidator is configured");
            return result;
        }

        try {
            // Only validate as access token
            TokenContent tokenContent = tokenValidator.createAccessToken(AccessTokenRequest.of(token.trim()));

            result.put(VALID, true);
            result.put(TOKEN_TYPE, "ACCESS_TOKEN");
            // Convert ClaimValue objects to simple strings for JSON-RPC serialization
            // (ClaimValue contains OffsetDateTime which Jackson cannot serialize by default)
            Map<String, String> simpleClaims = new HashMap<>();
            tokenContent.getClaims().forEach((key, value) -> {
                if (value != null) {
                    simpleClaims.put(key, value.getOriginalString());
                } else {
                    simpleClaims.put(key, null);
                }
            });
            result.put(CLAIMS, simpleClaims);
            result.put(ISSUER, tokenContent.getIssuer());

        } catch (TokenValidationException e) {
            // Token remains invalid (default state)
            result.put(ERROR, e.getMessage());
            result.put(DETAILS, "Access token validation failed");
        } catch (JsonException | IllegalArgumentException e) {
            // Handle JSON parsing errors and other token format issues
            result.put(ERROR, "Invalid token format: " + e.getMessage());
            result.put(DETAILS, "Token format is invalid");
        }

        return result;
    }

    /**
     * Get runtime health information.
     *
     * @return A map containing runtime health information
     */
   
    public Map<String, Object> getHealthInfo() {
        ObservedValidatorResolver.Outcome outcome = resolver.outcome();
        boolean configurationValid = outcome != ObservedValidatorResolver.Outcome.NOT_CONFIGURED;
        Map<String, Object> health = new HashMap<>();
        health.put("configurationValid", configurationValid);
        health.put(MESSAGE, configurationValid
                ? "All JWT components are healthy and operational (%s)".formatted(outcome.name())
                : "No TokenValidator is configured (%s)".formatted(outcome.name()));
        health.put(HEALTH_STATUS, configurationValid ? "UP" : "DOWN");
        return health;
    }

}
