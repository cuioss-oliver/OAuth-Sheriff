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
package de.cuioss.sheriff.token.validation.benchmark.delegates;

import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.benchmark.MockTokenRepository;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import io.jsonwebtoken.Jwts;
import org.openjdk.jmh.infra.Blackhole;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Delegate for error load benchmarks that test validation behavior under various error conditions.
 *
 * @author Oliver Wolff
 */
public class ErrorLoadDelegate extends BenchmarkDelegate {

    private final String expiredToken;
    private final String expiredTokenIssuer;
    private final String malformedToken;
    private final String invalidSignatureToken;
    private final int errorPercentage;
    private final AtomicInteger tokenIndex = new AtomicInteger(0);

    public ErrorLoadDelegate(TokenValidator tokenValidator, MockTokenRepository tokenRepository, int errorPercentage) {
        super(tokenValidator, tokenRepository);
        this.errorPercentage = errorPercentage;

        // Initialize error tokens
        InMemoryKeyMaterialHandler.IssuerKeyMaterial[] issuers = tokenRepository.getIssuers();
        if (issuers == null || issuers.length == 0) {
            throw new IllegalStateException("No issuers configured in token repository");
        }
        InMemoryKeyMaterialHandler.IssuerKeyMaterial expiredIssuer = issuers[0];
        this.expiredTokenIssuer = expiredIssuer.getIssuerIdentifier();
        this.expiredToken = createExpiredToken(expiredIssuer);
        this.malformedToken = "not.a.valid.jwt.token";
        this.invalidSignatureToken = createInvalidSignatureToken();
    }

    /**
     * Returns the next token from the valid-token rotation pool.
     * Use this to obtain the token that will be validated by {@link #validateValid(String)},
     * so metadata (issuer, size) can be derived from the same token that is actually validated.
     *
     * @return the next valid token from the pool
     */
    public String nextValidToken() {
        return tokenRepository.getToken(tokenIndex.getAndIncrement());
    }

    /**
     * Validates a valid token using full spectrum rotation.
     *
     * @return the validated access token content
     * @throws IllegalStateException if validation fails unexpectedly
     */
    public AccessTokenContent validateValid() {
        return validateValid(nextValidToken());
    }

    /**
     * Validates the given valid token.
     *
     * @param token the token to validate
     * @return the validated access token content
     * @throws IllegalStateException if validation fails unexpectedly
     */
    public AccessTokenContent validateValid(String token) {
        try {
            return validateToken(token);
        } catch (TokenValidationException e) {
            throw new IllegalStateException("Unexpected validation failure for valid token", e);
        }
    }

    /**
     * Validates an expired token.
     *
     * @return the expected validation exception
     * @throws IllegalStateException if validation unexpectedly succeeds
     */
    public Object validateExpired() {
        try {
            AccessTokenContent content = validateToken(expiredToken);
            throw new IllegalStateException(
                    "Validation of known-expired token unexpectedly succeeded: " + content);
        } catch (TokenValidationException e) {
            return e; // Expected
        }
    }

    /**
     * Validates a malformed token.
     *
     * @return the expected validation exception
     * @throws IllegalStateException if validation unexpectedly succeeds
     */
    public Object validateMalformed() {
        try {
            AccessTokenContent content = validateToken(malformedToken);
            throw new IllegalStateException(
                    "Validation of known-malformed token unexpectedly succeeded: " + content);
        } catch (TokenValidationException | IllegalArgumentException e) {
            return e; // Expected - malformed tokens can throw various validation exceptions
        }
    }

    /**
     * Validates a token with invalid signature.
     *
     * @return the expected validation exception
     * @throws IllegalStateException if validation unexpectedly succeeds
     */
    public Object validateInvalidSignature() {
        try {
            AccessTokenContent content = validateToken(invalidSignatureToken);
            throw new IllegalStateException(
                    "Validation of token with known-invalid signature unexpectedly succeeded: " + content);
        } catch (TokenValidationException e) {
            return e; // Expected
        }
    }

    /**
     * Validates mixed tokens based on error percentage.
     * Selects a token internally; use {@link #validateMixed(String, Blackhole)} when the
     * caller needs to know which token is validated (e.g. for JFR metadata).
     *
     * @param blackhole JMH blackhole to consume results
     * @return the validation result (token content or exception)
     */
    public Object validateMixed(Blackhole blackhole) {
        return validateMixed(selectToken(), blackhole);
    }

    /**
     * Validates the given token, tolerating validation failures (mixed valid/error load).
     *
     * @param token the token to validate
     * @param blackhole JMH blackhole to consume results
     * @return the validation result (token content or exception)
     */
    public Object validateMixed(String token, Blackhole blackhole) {
        try {
            AccessTokenContent result = validateToken(token);
            if (blackhole != null) {
                blackhole.consume(result);
            }
            return result;
        } catch (TokenValidationException e) {
            if (blackhole != null) {
                blackhole.consume(e);
            }
            return e;
        }
    }

    /**
     * Selects a token based on the error percentage, using full spectrum for valid tokens.
     *
     * @return the selected token
     */
    @SuppressWarnings("java:S2245") // ok for test-code
    public String selectToken() {
        // ThreadLocalRandom is safe for benchmarking - it provides thread-safe pseudorandom numbers
        int random = ThreadLocalRandom.current().nextInt(100);

        if (random < errorPercentage) {
            // Select an error token based on distribution
            // ThreadLocalRandom is appropriate here for distributing error types in benchmarks
            int errorType = ThreadLocalRandom.current().nextInt(3);
            return switch (errorType) {
                case 0 -> expiredToken;
                case 1 -> malformedToken;
                default -> invalidSignatureToken;
            };
        }

        // Return a token from the full spectrum for valid tokens
        return tokenRepository.getToken(tokenIndex.getAndIncrement());
    }

    /**
     * Gets the error type for a given token.
     *
     * @param token the token to check
     * @return the error type or "valid" if no error
     */
    public String getErrorType(String token) {
        if (token.equals(expiredToken)) {
            return "expired";
        } else if (token.equals(malformedToken)) {
            return "malformed";
        } else if (token.equals(invalidSignatureToken)) {
            return "invalid_signature";
        }
        return "valid";
    }

    /**
     * Gets the issuer identifier used for the expired token.
     * This is a real configured issuer, so the expired-token benchmark measures the
     * expiry path (not unknown-issuer rejection).
     *
     * @return the issuer identifier of the expired token
     */
    public String getExpiredTokenIssuer() {
        return expiredTokenIssuer;
    }

    /**
     * Gets the expired token used by {@link #validateExpired()}.
     *
     * @return the expired token
     */
    public String getExpiredToken() {
        return expiredToken;
    }

    /**
     * Creates a token that is signed by a real configured issuer's key but is already expired.
     * Signing with a configured issuer ensures the validator reaches the expiry check instead
     * of rejecting the token earlier for an unknown issuer.
     */
    private String createExpiredToken(InMemoryKeyMaterialHandler.IssuerKeyMaterial issuer) {
        String audience = tokenRepository.getConfig().getExpectedAudience();
        Instant past = Instant.now().minusSeconds(3600);

        return Jwts.builder()
                .header()
                .keyId(issuer.getKeyId())
                .and()
                .issuer(issuer.getIssuerIdentifier())
                .subject("benchmark-user")
                .audience().add(audience).and()
                .expiration(Date.from(past)) // Already expired
                .notBefore(Date.from(past.minusSeconds(60)))
                .issuedAt(Date.from(past.minusSeconds(120)))
                .id(UUID.randomUUID().toString())
                .claim("typ", "Bearer")
                .claim("azp", audience)
                .signWith(issuer.getPrivateKey())
                .compact();
    }

    private String createInvalidSignatureToken() {
        // Take a primary token and corrupt the signature
        String primaryToken = tokenRepository.getPrimaryToken();
        String[] parts = primaryToken.split("\\.");
        if (parts.length == 3) {
            // Modify the signature part
            return parts[0] + "." + parts[1] + ".invalidSignature123";
        }
        return "invalid.signature.token";
    }
}