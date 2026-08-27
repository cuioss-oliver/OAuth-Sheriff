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
package de.cuioss.sheriff.token.validation.test;

import com.dslplatform.json.DslJson;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.domain.token.IdTokenContent;
import de.cuioss.sheriff.token.validation.domain.token.TokenContent;
import de.cuioss.sheriff.token.validation.json.JwtHeader;
import de.cuioss.sheriff.token.validation.json.MapRepresentation;
import de.cuioss.sheriff.token.validation.jwks.JwksLoader;
import de.cuioss.sheriff.token.validation.pipeline.DecodedJwt;
import de.cuioss.sheriff.token.validation.security.SignatureAlgorithmPreferences;
import de.cuioss.sheriff.token.validation.test.generator.ClaimControlParameter;
import de.cuioss.sheriff.token.validation.test.generator.RoleGenerator;
import de.cuioss.sheriff.token.validation.test.generator.ScopeGenerator;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.test.generator.domain.EmailGenerator;
import de.cuioss.test.generator.domain.FullNameGenerator;
import de.cuioss.test.generator.domain.UUIDStringGenerator;
import io.jsonwebtoken.Jwts;
import lombok.Getter;

import java.io.IOException;
import java.security.PublicKey;
import java.time.OffsetDateTime;
import java.util.*;

/**
 * Implementation of TokenContent for testing purposes that allows for dynamic token generation.
 * <p>
 * This class is designed to:
 * <ul>
 *   <li>Take ClaimControlParameter and TokenType in the constructor</li>
 *   <li>Generate content using generators analogous to AccessTokenGenerator</li>
 *   <li>Provide mutators for content</li>
 *   <li>Generate the actual token representation on demand</li>
 *   <li>Use generators for keyId and signingAlgorithm aligned with SignatureAlgorithmPreferences</li>
 * </ul>
 * <p>
 * The token is created and signed using the Jwts library when getRawToken() is called.
 * <p>
 * The keyId and signingAlgorithm are generated using Generators.fixedValues() with a defined list.
 * Uses RS256 as the default test algorithm and the default key ID.
 */
public class TestTokenHolder {

    public static final String TEST_ISSUER = "Token-Test-testIssuer";
    /**
     * Standard test audience value - represents the intended recipient of the token.
     * Used in the 'aud' claim to specify which service/API the token is for.
     *
     * <p>In OAuth2/OIDC semantics, the audience identifies the resource server(s) that should
     * accept and validate the token. This is typically a service URL or identifier.</p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3">RFC 7519 Section 4.1.3</a>
     */
    public static final String TEST_AUDIENCE = "test-audience";

    /**
     * Standard test client ID - represents the OAuth2 client identifier.
     * Used for client identification, authorized party claims, and client-specific validations.
     *
     * <p>In OAuth2/OIDC semantics, the client ID identifies the OAuth2 client application that
     * requested the token. This is used in the 'azp' (authorized party) claim and for client
     * validation. It is semantically distinct from the audience to properly model real-world
     * OAuth2/OIDC scenarios where clients and resource servers are different entities.</p>
     *
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9068">RFC 9068 - JWT Profile for OAuth 2.0</a>
     */
    public static final String TEST_CLIENT_ID = "test-client-app";

    /**
     * Generator for signing algorithms.
     * Uses RS256 as the default test algorithm.
     */
    private static final TypedGenerator<InMemoryKeyMaterialHandler.Algorithm> ALGORITHM_GENERATOR =
            Generators.fixedValues(InMemoryKeyMaterialHandler.Algorithm.RS256);

    /**
     * Generator for key IDs using a fixed list.
     * Uses the default key ID for test consistency.
     */
    private static final TypedGenerator<String> KEY_ID_GENERATOR =
            Generators.fixedValues(InMemoryKeyMaterialHandler.DEFAULT_KEY_ID);

    @Getter
    private final TokenType tokenType;
    private final ClaimControlParameter claimControl;
    private final String uniqueId;
    @Getter
    private String keyId;
    @Getter
    private InMemoryKeyMaterialHandler.Algorithm signingAlgorithm;
    @Getter
    private Map<String, ClaimValue> claims;
    private String cachedRawToken;

    /**
     * Constructor for creating a token holder with specific claim control parameters.
     * The keyId and signingAlgorithm are generated using Generators.fixedValues() with a defined list.
     * Uses RS256 as the default test algorithm and the default key ID.
     *
     * @param tokenType    the type of token to generate
     * @param claimControl the parameter object controlling which claims should be included or excluded
     */
    public TestTokenHolder(TokenType tokenType, ClaimControlParameter claimControl) {
        this.tokenType = tokenType;
        this.claimControl = claimControl;
        this.uniqueId = new UUIDStringGenerator().next();
        this.keyId = KEY_ID_GENERATOR.next();
        this.signingAlgorithm = ALGORITHM_GENERATOR.next();
        this.claims = generateClaims();
        this.cachedRawToken = null; // Will be generated on demand
    }

    /**
     * Gets the subject from the claims map.
     *
     * @return an Optional containing the subject if present
     */
    public Optional<String> getSubject() {
        var subClaim = claims.get(ClaimName.SUBJECT.getName());
        if (subClaim == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(subClaim.getOriginalString());
    }

    /**
     * Gets the issuer from the claims map.
     *
     * @return the issuer string, or throws if not present
     */
    public String getIssuer() {
        var issuerClaim = claims.get(ClaimName.ISSUER.getName());
        if (issuerClaim == null) {
            throw new IllegalStateException("Issuer claim not present");
        }
        return issuerClaim.getOriginalString();
    }

    public String getRawToken() {
        // If we already have a cached token and no mutations have occurred, return it
        if (cachedRawToken != null) {
            return cachedRawToken;
        }

        try {
            // Create a JWT builder
            var builder = Jwts.builder();

            // Add header parameters
            builder.header().add("kid", keyId).and();

            // Add all claims from the TokenContent
            for (Map.Entry<String, ClaimValue> entry : claims.entrySet()) {
                String claimName = entry.getKey();
                ClaimValue claimValue = entry.getValue();

                // Skip null values
                if (claimValue == null || claimValue.getOriginalString() == null) {
                    continue;
                }

                // Handle different claim value types
                switch (claimValue.getType()) {
                    case STRING_LIST:
                        // For list values, add as a list
                        builder.claim(claimName, claimValue.getAsList());
                        break;
                    case DATETIME:
                        // For date-time values, add as a Date
                        OffsetDateTime dateTime = claimValue.getDateTime();
                        if (dateTime != null) {
                            builder.claim(claimName, Date.from(dateTime.toInstant()));
                        }
                        break;
                    case STRING:
                    default:
                        // For string values, add as a string
                        builder.claim(claimName, claimValue.getOriginalString());
                        break;
                }
            }

            // Sign the token with the private key for the specified algorithm
            builder.signWith(InMemoryKeyMaterialHandler.getPrivateKey(
                    signingAlgorithm,
                    keyId));

            // Build and return the JWT string
            cachedRawToken = builder.compact();
            return cachedRawToken;
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new IllegalStateException("Failed to generate JWT token", e);
        }
    }

    /**
     * Sets the key ID used in the JWT header.
     *
     * @param keyId the key ID to use
     * @return this instance for method chaining
     */
    public TestTokenHolder withKeyId(String keyId) {
        this.keyId = keyId;
        // Invalidate cached token since header has changed
        cachedRawToken = null;
        return this;
    }

    /**
     * Sets the signing algorithm used for the JWT.
     *
     * @param signingAlgorithm the signing algorithm to use
     * @return this instance for method chaining
     */
    public TestTokenHolder withSigningAlgorithm(InMemoryKeyMaterialHandler.Algorithm signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
        // Invalidate cached token since header has changed
        cachedRawToken = null;
        return this;
    }

    /**
     * Sets the signing algorithm to ES256 for testing ECDSA signature format issues.
     * 
     * <p><strong>Important:</strong> JJWT generates ECDSA signatures in IEEE P1363 format 
     * (raw R,S concatenation), but the JDK ECDSA verification expects ASN.1/DER format.
     * This causes signature validation failures until format conversion is implemented.</p>
     * 
     * @return this instance for method chaining
     */
    public TestTokenHolder withES256IeeeP1363Format() {
        return withSigningAlgorithm(InMemoryKeyMaterialHandler.Algorithm.ES256);
    }

    /**
     * Gets the public key material associated with the current key ID and signing algorithm.
     *
     * @return the public key
     */
    public PublicKey getPublicKey() {
        return InMemoryKeyMaterialHandler.getPublicKey(signingAlgorithm, keyId);
    }

    /**
     * Gets the public key material as a JwksLoader.
     * This is a shorthand for accessing the key material currently configured.
     *
     * @return a JwksLoader containing the public key
     */
    public JwksLoader getPublicKeyAsLoader() {
        return InMemoryKeyMaterialHandler.createJwksLoader(signingAlgorithm, keyId, new SecurityEventCounter());
    }

    /**
     * Gets an IssuerConfig configured according to the current token configuration.
     * This method creates an IssuerConfig with the issuer, audience, and client ID
     * from the current token, and configures it with the public key material.
     *
     * <p>Note: This method does not initialize the security event counter.
     * It is the client's responsibility to initialize the security event counter
     * using {@code issuerConfig.initJWKSLoader(securityEventCounter)}
     * if security event tracking is needed.
     *
     * @return a configured IssuerConfig
     */
    public IssuerConfig getIssuerConfig() {
        // Get the issuer from the claims
        String issuer = TEST_ISSUER;
        if (claims.containsKey(ClaimName.ISSUER.getName())) {
            issuer = claims.get(ClaimName.ISSUER.getName()).getOriginalString();
        }

        // Always use the fixed TEST_AUDIENCE as expected audience to avoid circular dependency
        // Tests that need different expected audiences should create their own IssuerConfig
        List<String> audience = List.of(TEST_AUDIENCE);

        // Always use the fixed TEST_CLIENT_ID as expected client ID to avoid circular dependency
        // Tests that need different expected client IDs should create their own IssuerConfig

        // Create the JWKS content
        String jwksContent = InMemoryKeyMaterialHandler.createJwks(signingAlgorithm, keyId);

        // Build and return the IssuerConfig using the new issuerIdentifier field
        var config = IssuerConfig.builder()
                .issuerIdentifier(issuer)
                .jwksContent(jwksContent)
                .algorithmPreferences(new SignatureAlgorithmPreferences());

        // Add audience and client ID
        for (String aud : audience) {
            config.expectedAudience(aud);
        }
        config.expectedClientId(TEST_CLIENT_ID);

        // Build the config
        return config.build();
    }

    /**
     * Adds or replaces a claim in the token.
     *
     * @param name  the claim name
     * @param value the claim value
     * @return this instance for method chaining
     */
    public TestTokenHolder withClaim(String name, ClaimValue value) {
        claims.put(name, value);
        // Invalidate cached token since claims have changed
        cachedRawToken = null;
        return this;
    }

    /**
     * Removes a claim from the token.
     *
     * @param name the claim name to remove
     * @return this instance for method chaining
     */
    public TestTokenHolder withoutClaim(String name) {
        claims.remove(name);
        // Invalidate cached token since claims have changed
        cachedRawToken = null;
        return this;
    }

    /**
     * Replaces all claims in the token.
     *
     * @param newClaims the new claims map
     * @return this instance for method chaining
     */
    public TestTokenHolder withClaims(Map<String, ClaimValue> newClaims) {
        this.claims = new HashMap<>(newClaims);
        // Invalidate cached token since claims have changed
        cachedRawToken = null;
        return this;
    }

    /**
     * Regenerates all claims based on the claim control parameter.
     *
     * @return this instance for method chaining
     */
    public TestTokenHolder regenerateClaims() {
        this.claims = generateClaims();
        // Invalidate cached token since claims have changed
        cachedRawToken = null;
        return this;
    }

    /**
     * Gets the audience claim from the token.
     *
     * @return the audience as a list of strings, or empty list if not present
     */
    public Set<String> getAudience() {
        if (claims.containsKey(ClaimName.AUDIENCE.getName())) {
            return new LinkedHashSet<>(claims.get(ClaimName.AUDIENCE.getName()).getAsList());
        }
        return Set.of();
    }

    /**
     * Sets the audience claim in the token.
     *
     * @param audience the audience as a list of strings
     * @return this instance for method chaining
     */
    public TestTokenHolder withAudience(List<String> audience) {
        claims.put(ClaimName.AUDIENCE.getName(), ClaimValue.forList(
                String.join(",", audience), audience));
        // Invalidate cached token since claims have changed
        cachedRawToken = null;
        return this;
    }

    /**
     * Gets the authorized party (azp) claim from the token.
     *
     * @return the authorized party as a string, or null if not present
     */
    public String getAuthorizedParty() {
        if (claims.containsKey(ClaimName.AUTHORIZED_PARTY.getName())) {
            return claims.get(ClaimName.AUTHORIZED_PARTY.getName()).getOriginalString();
        }
        return null;
    }

    /**
     * Sets the authorized party (azp) claim in the token.
     *
     * @param authorizedParty the authorized party as a string
     * @return this instance for method chaining
     */
    public TestTokenHolder withAuthorizedParty(String authorizedParty) {
        if (authorizedParty == null) {
            claims.remove(ClaimName.AUTHORIZED_PARTY.getName());
        } else {
            claims.put(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString(authorizedParty));
        }
        // Invalidate cached token since claims have changed
        cachedRawToken = null;
        return this;
    }

    /**
     * Converts this TestTokenHolder to a DecodedJwt.
     * <p>
     * This method creates a DecodedJwt instance from the current token content.
     * It uses the io.jsonwebtoken library to parse the JWT string and extract
     * the header, body, and signature.
     *
     * @return a DecodedJwt instance representing this token
     * @throws IllegalStateException if the conversion fails
     */
    public DecodedJwt asDecodedJwt() {
        try {
            // Get the raw token
            String signedJwt = getRawToken();

            // Split the JWT string into parts to get JSON directly
            String[] parts = signedJwt.split("\\.");
            if (parts.length < 2) {
                throw new IllegalArgumentException("Invalid JWT format: missing header or payload");
            }

            // Decode the header and payload JSON strings directly
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));

            // Parse using DSL-JSON directly from JSON strings
            DslJson<Object> dslJson = ParserConfig.builder().build().getDslJson();
            byte[] headerBytes = headerJson.getBytes();
            JwtHeader header = dslJson.deserialize(JwtHeader.class, headerBytes, headerBytes.length);
            MapRepresentation body = MapRepresentation.fromJson(dslJson, payloadJson);

            // Get the signature from the parts
            var signature = parts.length > 2 ? parts[2] : "";

            if (header == null) {
                throw new IllegalStateException("Failed to parse JWT header from: " + headerJson);
            }

            // Create and return the DecodedJwt
            return new DecodedJwt(header, body, signature, parts, signedJwt);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse JWT with DSL-JSON", e);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Invalid JWT format", e);
        }
    }


    /**
     * Converts this TestTokenHolder to an AccessTokenContent.
     * <p>
     * This method creates an AccessTokenContent instance from the current token content.
     * It extracts the email from the claims and passes it to the AccessTokenContent constructor.
     *
     * @return an AccessTokenContent instance representing this token
     * @throws IllegalStateException if the token type is not ACCESS_TOKEN
     */
    public AccessTokenContent asAccessTokenContent() {
        if (tokenType != TokenType.ACCESS_TOKEN) {
            throw new IllegalStateException("Cannot convert token of type " + tokenType + " to AccessTokenContent. Only ACCESS_TOKEN is supported.");
        }

        return new AccessTokenContent(claims, getRawToken());
    }

    /**
     * Converts this TestTokenHolder to an IdTokenContent.
     *
     * @return an IdTokenContent instance representing this token
     * @throws IllegalStateException if the token type is not ID_TOKEN
     */
    public IdTokenContent asIdTokenContent() {
        if (tokenType != TokenType.ID_TOKEN) {
            throw new IllegalStateException("Cannot convert token of type " + tokenType + " to IdTokenContent. Only ID_TOKEN is supported.");
        }

        return new IdTokenContent(claims, getRawToken());
    }

    /**
     * Converts this TestTokenHolder to the appropriate TokenContent subtype.
     *
     * @return a TokenContent instance representing this token
     * @throws IllegalStateException if the token type is not ACCESS_TOKEN or ID_TOKEN
     */
    public TokenContent asTokenContent() {
        return switch (tokenType) {
            case ACCESS_TOKEN -> asAccessTokenContent();
            case ID_TOKEN -> asIdTokenContent();
            default -> throw new IllegalStateException("Cannot convert token of type " + tokenType + " to TokenContent.");
        };
    }

    private Map<String, ClaimValue> generateClaims() {
        Map<String, ClaimValue> claimsMap = new HashMap<>();

        // Add common mandatory claims unless they should be missing
        if (!claimControl.isMissingIssuer()) {
            claimsMap.put(ClaimName.ISSUER.getName(), ClaimValue.forPlainString(TEST_ISSUER));
        }

        if (!claimControl.isMissingSubject()) {
            claimsMap.put(ClaimName.SUBJECT.getName(), ClaimValue.forPlainString("test-subject"));
        }

        if (!claimControl.isMissingExpiration()) {
            // Add expiration time
            OffsetDateTime expirationTime;
            if (claimControl.isExpiredToken()) {
                // Set expiration to 1 hour in the past
                expirationTime = OffsetDateTime.now().minusHours(1);
            } else {
                // Set expiration to 1 hour in the future
                expirationTime = OffsetDateTime.now().plusHours(1);
            }
            claimsMap.put(ClaimName.EXPIRATION.getName(), ClaimValue.forDateTime(
                    String.valueOf(expirationTime.toEpochSecond()), expirationTime));
        }

        if (!claimControl.isMissingIssuedAt()) {
            // Add issued at time (now)
            OffsetDateTime issuedAtTime = OffsetDateTime.now();
            claimsMap.put(ClaimName.ISSUED_AT.getName(), ClaimValue.forDateTime(
                    String.valueOf(issuedAtTime.toEpochSecond()), issuedAtTime));
        }

        // Add token ID using the stored uniqueId
        claimsMap.put(ClaimName.TOKEN_ID.getName(), ClaimValue.forPlainString(uniqueId));

        // Always add roles using RoleGenerator (needed for tests)
        Set<String> roles = new RoleGenerator().next();
        claimsMap.put("roles", ClaimValue.forList(
                String.join(",", roles), new ArrayList<>(roles)));

        // Handle token complexity
        if (claimControl.getTokenComplexity() == ClaimControlParameter.TokenComplexity.COMPLEX) {
            // Add nested claim
            Map<String, Object> nestedClaim = new HashMap<>();
            nestedClaim.put("attr1", "value1");
            nestedClaim.put("attr2", true);
            nestedClaim.put("attr3", 12345);
            claimsMap.put("complex_claim", ClaimValue.forPlainString(nestedClaim.toString()));

            // Add extra claims
            for (int i = 0; i < 5; i++) {
                claimsMap.put("extra_claim_" + i, ClaimValue.forPlainString(Generators.letterStrings(50, 50).next()));
            }
        }

        // Handle token size
        int paddingLength = 0;
        switch (claimControl.getTokenSize()) {
            case MEDIUM:
                paddingLength = 4 * 1024; // Aim for roughly 5KB
                break;
            case LARGE:
                paddingLength = 9 * 1024; // Aim for roughly 10KB
                break;
            case SMALL:
            default:
                // No padding needed
                break;
        }

        if (paddingLength > 0) {
            claimsMap.put("padding", ClaimValue.forPlainString(Generators.letterStrings(paddingLength, paddingLength).next()));
        }

        // Add type-specific claims
        if (!claimControl.isMissingTokenType()) {
            switch (tokenType) {
                case ACCESS_TOKEN:
                    // Add token type
                    claimsMap.put(ClaimName.TYPE.getName(), ClaimValue.forPlainString("Bearer"));

                    // Add scope (mandatory for ACCESS_TOKEN) unless it should be missing
                    if (!claimControl.isMissingScope()) {
                        String scopeValue = new ScopeGenerator().next();
                        claimsMap.put(ClaimName.SCOPE.getName(), ClaimValue.forList(
                                scopeValue, new ArrayList<>(ScopeGenerator.splitScopes(scopeValue))));
                    }

                    // Add authorized party claim (azp) - required by TokenClaimValidator unless it should be missing
                    if (!claimControl.isMissingAuthorizedParty()) {
                        claimsMap.put(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString(TEST_CLIENT_ID));
                    }

                    // Add audience claim - required by TokenClaimValidator unless it should be missing
                    // Note: Using the same value for both azp and audience claims is correct in most cases,
                    // but tests should be able to override these values to test different scenarios
                    if (!claimControl.isMissingAudience()) {
                        List<String> audienceList = List.of(TEST_AUDIENCE);
                        claimsMap.put(ClaimName.AUDIENCE.getName(), ClaimValue.forList(
                                String.join(",", audienceList), audienceList));
                    }
                    break;

                case ID_TOKEN:
                    // Add token type
                    claimsMap.put(ClaimName.TYPE.getName(), ClaimValue.forPlainString("ID"));

                    // Add audience (mandatory for ID_TOKEN) unless it should be missing
                    if (!claimControl.isMissingAudience()) {
                        List<String> audienceList = List.of(TEST_AUDIENCE);
                        claimsMap.put(ClaimName.AUDIENCE.getName(), ClaimValue.forList(
                                String.join(",", audienceList), audienceList));
                    }

                    var names = new FullNameGenerator(Locale.ENGLISH);
                    // Add some optional claims typical for ID tokens
                    claimsMap.put(ClaimName.EMAIL.getName(), ClaimValue.forPlainString(new EmailGenerator().next()));
                    claimsMap.put(ClaimName.NAME.getName(), ClaimValue.forPlainString(names.next()));
                    claimsMap.put(ClaimName.PREFERRED_USERNAME.getName(), ClaimValue.forPlainString(names.next()));

                    // Add authorized party claim (azp) - required by TokenClaimValidator unless it should be missing
                    if (!claimControl.isMissingAuthorizedParty()) {
                        claimsMap.put(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString(TEST_CLIENT_ID));
                    }
                    break;

                case REFRESH_TOKEN:
                    // Add token type
                    claimsMap.put(ClaimName.TYPE.getName(), ClaimValue.forPlainString("Refresh"));
                    break;

                default:
                    // Should not happen - all known token types are handled above
                    break;
            }
        }

        return claimsMap;
    }
}
