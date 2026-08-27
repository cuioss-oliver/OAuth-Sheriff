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
package de.cuioss.sheriff.token.validation.pipeline;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.claim.mapper.ClaimMapper;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.domain.token.IdTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.json.MapRepresentation;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Builder for creating token content objects from decoded JWT tokens.
 * <p>
 * This class is responsible for transforming decoded JWT tokens into strongly-typed
 * token content objects for further processing in the application.
 * <p>
 * It supports creating different types of tokens:
 * <ul>
 *   <li>Access Tokens - via {@link #createAccessToken}</li>
 *   <li>ID Tokens - via {@link #createIdToken}</li>
 * </ul>
 * <p>
 * During token creation, the builder extracts and maps claims from the token body
 * using appropriate claim mappers based on the issuer configuration or standard claim names.
 * <p>
 * For more details on the token building process, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#token-validation-pipeline">Token Validation Pipeline</a>
 *
 * @apiNote This class is internal to Token-Sheriff and not part of the public API.
 * @since 1.0
 * @author Oliver Wolff
 */
public class TokenBuilder {

    // Combined mapper lookup to avoid runtime checks
    private final Map<String, ClaimMapper> allMappers;

    /**
     * Constructs a TokenBuilder with the specified IssuerConfig.
     *
     * @param issuerConfig the issuer configuration
     */
    public TokenBuilder(IssuerConfig issuerConfig) {
        // IssuerConfig.claimMappers is never null (defaults to Map.of() in constructor)
        Map<String, ClaimMapper> customMappers = Map.copyOf(issuerConfig.getClaimMappers());

        Map<String, ClaimMapper> tempMappers = new HashMap<>();

        for (ClaimName claimName : ClaimName.values()) {
            tempMappers.put(claimName.getName(), claimName.getClaimMapper());
        }

        // Add custom mappers, which override standard ones
        tempMappers.putAll(customMappers);

        this.allMappers = Map.copyOf(tempMappers);
    }

    /**
     * Creates an AccessTokenContent from a decoded JWT.
     *
     * @param decodedJwt the decoded JWT
     * @return an Optional containing the AccessTokenContent if it could be created, empty otherwise
     * @throws TokenValidationException if a claim value is malformed and cannot be mapped
     */
    public Optional<AccessTokenContent> createAccessToken(DecodedJwt decodedJwt) {
        MapRepresentation body = decodedJwt.body();
        // Design Decision: Optional.empty() is the correct return for empty body.
        // Caller (AccessTokenValidationPipeline) handles this case explicitly.
        if (body.isEmpty()) {
            return Optional.empty();
        }

        Map<String, ClaimValue> claims = extractClaims(body);

        return Optional.of(new AccessTokenContent(claims, decodedJwt.rawToken()));
    }

    /**
     * Creates an IdTokenContent from a decoded JWT.
     *
     * @param decodedJwt the decoded JWT
     * @return an Optional containing the IdTokenContent if it could be created, empty otherwise
     * @throws TokenValidationException if a claim value is malformed and cannot be mapped
     */
    public Optional<IdTokenContent> createIdToken(DecodedJwt decodedJwt) {
        MapRepresentation body = decodedJwt.body();
        if (body.isEmpty()) {
            return Optional.empty();
        }

        Map<String, ClaimValue> claims = extractClaims(body);

        return Optional.of(new IdTokenContent(claims, decodedJwt.rawToken()));
    }


    /**
     * Extracts claims from a MapRepresentation using proper claim mappers.
     *
     * @param mapRepresentation the MapRepresentation containing claims
     * @return a map of claim names to claim values
     */
    private Map<String, ClaimValue> extractClaims(MapRepresentation mapRepresentation) {
        Map<String, ClaimValue> claims = HashMap.newHashMap(mapRepresentation.size());

        for (String key : mapRepresentation.keySet()) {
            // Try to find a configured claim mapper for this key
            ClaimMapper mapper = allMappers.get(key);

            if (mapper != null) {
                // Use the configured mapper (either built-in or custom).
                // Mappers (including custom SPI implementations) can throw arbitrary runtime
                // exceptions on malformed claim values (e.g. a string-typed 'exp'). Translate
                // to TokenValidationException to honor the documented contract of TokenValidator.
                ClaimValue claimValue;
                try {
                    claimValue = mapper.map(mapRepresentation, key);
                } catch (TokenValidationException e) {
                    throw e;
                }
                // cui-rewrite:disable InvalidExceptionUsageRecipe
                // Custom SPI mappers can throw arbitrary runtime exceptions — the broad
                // catch is deliberate; TokenValidationException is rethrown above.
                catch (RuntimeException e) {
                    throw new TokenValidationException(
                            SecurityEventCounter.EventType.MISSING_CLAIM,
                            "Malformed claim '" + key + "': " + e.getMessage(),
                            e
                    );
                }
                if (claimValue != null) {
                    claims.put(key, claimValue);
                }
            } else {
                // Fallback for unknown claims - use identity mapping
                Optional<String> stringValue = mapRepresentation.getString(key);
                if (stringValue.isPresent()) {
                    claims.put(key, ClaimValue.forPlainString(stringValue.get()));
                } else {
                    // Handle non-string values by converting to string
                    Optional<Object> value = mapRepresentation.getValue(key);
                    value.ifPresent(o -> claims.put(key, ClaimValue.forPlainString(o.toString())));
                }
            }
        }

        return claims;
    }


    /**
     * Extracts claims for a Refresh-Token from a MapRepresentation.
     *
     * @param mapRepresentation the MapRepresentation containing claims
     * @return a map of claim names to claim values
     */
    public static Map<String, ClaimValue> extractClaimsForRefreshToken(MapRepresentation mapRepresentation) {
        Map<String, ClaimValue> claims = HashMap.newHashMap(mapRepresentation.size());

        for (String key : mapRepresentation.keySet()) {
            // Convert Map entry to ClaimValue
            Optional<Object> value = mapRepresentation.getValue(key);
            if (value.isPresent()) {
                Object valueObj = value.get();
                if (valueObj instanceof String stringValue) {
                    claims.put(key, ClaimValue.forPlainString(stringValue));
                } else {
                    claims.put(key, ClaimValue.forPlainString(valueObj.toString()));
                }
            }
        }

        return claims;
    }
}
