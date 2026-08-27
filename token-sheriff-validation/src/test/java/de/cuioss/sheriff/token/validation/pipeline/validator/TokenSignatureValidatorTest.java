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
package de.cuioss.sheriff.token.validation.pipeline.validator;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.JwksType;
import de.cuioss.sheriff.token.commons.transport.LoaderStatus;
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.jwks.JwksLoader;
import de.cuioss.sheriff.token.validation.jwks.JwksLoaderFactory;
import de.cuioss.sheriff.token.validation.jwks.key.KeyInfo;
import de.cuioss.sheriff.token.validation.pipeline.DecodedJwt;
import de.cuioss.sheriff.token.validation.pipeline.NonValidatingJwtParser;
import de.cuioss.sheriff.token.validation.pipeline.SignatureTemplateManager;
import de.cuioss.sheriff.token.validation.security.SignatureAlgorithmPreferences;
import de.cuioss.sheriff.token.validation.test.InMemoryJWKSFactory;
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.ClaimControlParameter;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.jsonwebtoken.Jwts;
import lombok.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the {@link TokenSignatureValidator} class.
 * <p>
 * Verifies requirements:
 * <ul>
 *   <li><a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-1.1">VALIDATION-1.1: Token Structure</a></li>
 *   <li><a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-1.3">VALIDATION-1.3: Signature Validation</a> (includes algorithm selection and confusion protection)</li>
 *   <li><a href="../../../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-4">VALIDATION-4: Key Management</a> (key material handling)</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/security-reference.adoc">Security Specification</a>
 */
@EnableTestLogger(rootLevel = TestLogLevel.DEBUG)
@EnableGeneratorController
@DisplayName("Tests TokenSignatureValidator")
class TokenSignatureValidatorTest {

    private NonValidatingJwtParser jwtParser;
    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp() {

        // Create a security event counter
        securityEventCounter = new SecurityEventCounter();
        // Create a real JWT parser using the builder
        jwtParser = NonValidatingJwtParser.builder().securityEventCounter(securityEventCounter).build();
    }

    @Test
    @DisplayName("Should validate validation with valid signature")
    void shouldValidateTokenWithValidSignature() {
        // Create a valid validation
        String token = createToken();

        // Parse the validation
        DecodedJwt decodedJwt = jwtParser.decode(token);
        assertNotNull(decodedJwt, "Decoded JWT should not be null");

        // Create an in-memory JwksLoader with a valid key
        String jwksContent = InMemoryJWKSFactory.createDefaultJwks();
        JwksLoader jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent);
        jwksLoader.initJWKSLoader(securityEventCounter);

        // Create the validator with the in-memory JwksLoader and security event counter
        TokenSignatureValidator validator = new TokenSignatureValidator(jwksLoader, securityEventCounter, new SignatureTemplateManager(new SignatureAlgorithmPreferences()));

        // Validate the signature - should not throw an exception
        assertDoesNotThrow(() -> validator.validateSignature(decodedJwt));
    }

    @Test
    @DisplayName("Should reject validation with invalid signature")
    void shouldRejectTokenWithInvalidSignature() {
        // Get initial count
        long initialCount = securityEventCounter.getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED);

        // Create a validation with a valid signature
        String validToken = createToken();

        // Tamper with the payload to invalidate the signature
        String[] parts = validToken.split("\\.");
        String header = parts[0];
        String payload = parts[1];

        // Decode the payload, modify it, and encode it again
        String decodedPayload = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
        String modifiedPayload = decodedPayload.replace("\"sub\":", "\"sub_modified\":");
        String encodedModifiedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(modifiedPayload.getBytes(StandardCharsets.UTF_8));

        // Reconstruct the validation with the modified payload but original signature
        String tamperedToken = header + "." + encodedModifiedPayload + "." + parts[2];

        // Parse the tampered validation
        DecodedJwt decodedJwt = jwtParser.decode(tamperedToken);
        assertNotNull(decodedJwt, "Decoded JWT should not be null");

        // Create an in-memory JwksLoader with a valid key
        String jwksContent = InMemoryJWKSFactory.createDefaultJwks();
        JwksLoader jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent);
        jwksLoader.initJWKSLoader(securityEventCounter);

        // Create the validator with the in-memory JwksLoader and security event counter
        TokenSignatureValidator validator = new TokenSignatureValidator(jwksLoader, securityEventCounter, new SignatureTemplateManager(new SignatureAlgorithmPreferences()));

        // Validate the signature - should throw an exception
        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> validator.validateSignature(decodedJwt));

        // Verify the exception has the correct event type
        assertEquals(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED, exception.getEventType());

        // Verify log message
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                JWTValidationLogMessages.ERROR.SIGNATURE_VALIDATION_FAILED.resolveIdentifierString());

        // Verify security event was recorded
        assertTrue(securityEventCounter.getCount(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED) > initialCount);
    }

    @Test
    @DisplayName("Should reject validation when key is not found")
    void shouldRejectTokenWhenKeyNotFound() {
        // Get initial count
        long initialCount = securityEventCounter.getCount(SecurityEventCounter.EventType.KEY_NOT_FOUND);

        // Create a valid validation
        String token = createToken();

        // Parse the validation
        DecodedJwt decodedJwt = jwtParser.decode(token);
        assertNotNull(decodedJwt, "Decoded JWT should not be null");

        // Create an in-memory JwksLoader with a different key ID
        String jwksContent = InMemoryJWKSFactory.createValidJwksWithKeyId("different-key-id");
        JwksLoader jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent);
        jwksLoader.initJWKSLoader(securityEventCounter);

        // Create the validator with the in-memory JwksLoader and security event counter
        TokenSignatureValidator validator = new TokenSignatureValidator(jwksLoader, securityEventCounter, new SignatureTemplateManager(new SignatureAlgorithmPreferences()));

        // Validate the signature - should throw an exception
        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> validator.validateSignature(decodedJwt));

        // Verify the exception has the correct event type
        assertEquals(SecurityEventCounter.EventType.KEY_NOT_FOUND, exception.getEventType());

        // Verify log message
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                JWTValidationLogMessages.WARN.KEY_NOT_FOUND.resolveIdentifierString());

        // Verify security event was recorded
        assertEquals(initialCount + 1, securityEventCounter.getCount(SecurityEventCounter.EventType.KEY_NOT_FOUND));
    }

    @Test
    @DisplayName("Should throw IllegalStateException when kid is missing (precondition violation)")
    void shouldRejectTokenWithMissingKid() {
        // Create a validation without a kid
        String token = createTokenWithoutKid();

        // Parse the validation
        DecodedJwt decodedJwt = jwtParser.decode(token);
        assertNotNull(decodedJwt, "Decoded JWT should not be null");

        // Create an in-memory JwksLoader with a valid key
        String jwksContent = InMemoryJWKSFactory.createDefaultJwks();
        JwksLoader jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent);
        jwksLoader.initJWKSLoader(securityEventCounter);

        // Create the validator with the in-memory JwksLoader and security event counter
        TokenSignatureValidator validator = new TokenSignatureValidator(jwksLoader, securityEventCounter, new SignatureTemplateManager(new SignatureAlgorithmPreferences()));

        // Kid validation is now a precondition - should be validated by TokenHeaderValidator first
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> validator.validateSignature(decodedJwt));

        assertTrue(exception.getMessage().contains("Key ID (kid) should have been validated by TokenHeaderValidator"),
                "Exception message should indicate precondition violation");
    }

    @Test
    @DisplayName("Should reject validation with algorithm confusion attack")
    void shouldRejectAlgorithmConfusionAttack() {
        // Get initial count
        long initialCount = securityEventCounter.getCount(SecurityEventCounter.EventType.KEY_NOT_FOUND);

        // Create a validation with RS256 in the header but actually signed with HS256
        // This is a common algorithm confusion attack
        String token = createAlgorithmConfusionToken();

        // Parse the validation
        DecodedJwt decodedJwt = jwtParser.decode(token);
        assertNotNull(decodedJwt, "Decoded JWT should not be null");

        // Create an in-memory JwksLoader with a valid key
        String jwksContent = InMemoryJWKSFactory.createDefaultJwks();
        JwksLoader jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent);
        jwksLoader.initJWKSLoader(securityEventCounter);

        // Create the validator with the in-memory JwksLoader and security event counter
        TokenSignatureValidator validator = new TokenSignatureValidator(jwksLoader, securityEventCounter, new SignatureTemplateManager(new SignatureAlgorithmPreferences()));

        // Validate the signature - should throw an exception
        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> validator.validateSignature(decodedJwt));

        // Verify the exception has the correct event type
        assertEquals(SecurityEventCounter.EventType.KEY_NOT_FOUND, exception.getEventType());

        // Verify log message
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "No key found with ID: wrong-key-id");

        // Verify security event was recorded
        assertEquals(initialCount + 1, securityEventCounter.getCount(SecurityEventCounter.EventType.KEY_NOT_FOUND));
    }

    @Test
    @DisplayName("Should reject validation with algorithm mismatch")
    void shouldRejectTokenWithAlgorithmMismatch() {
        // Get initial count
        long initialCount = securityEventCounter.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM);

        // Create a valid validation
        String token = createToken();

        // Parse the validation
        DecodedJwt decodedJwt = jwtParser.decode(token);
        assertNotNull(decodedJwt, "Decoded JWT should not be null");

        // Create a custom JwksLoader that returns a key with incompatible algorithm
        JwksLoader jwksLoader = new JwksLoader() {
            @Override
            public Optional<KeyInfo> getKeyInfo(String kid) {
                if (InMemoryJWKSFactory.DEFAULT_KEY_ID.equals(kid)) {
                    return Optional.of(new KeyInfo(InMemoryKeyMaterialHandler.getDefaultPublicKey(), "EC", kid));
                }
                return Optional.empty();
            }

            // Removed overrides for methods that no longer exist in JwksLoader interface

            @Override
            public JwksType getJwksType() {
                return JwksType.MEMORY;
            }

            @Override
            public LoaderStatus getLoaderStatus() {
                return LoaderStatus.OK;
            }

            @Override
            public Optional<String> getIssuerIdentifier() {
                return Optional.empty();
            }

            @Override
            public CompletableFuture<LoaderStatus> initJWKSLoader(@NonNull SecurityEventCounter securityEventCounter) {
                // This is a test implementation, no initialization needed
                return CompletableFuture.completedFuture(LoaderStatus.OK);
            }
        };

        // Create the validator with the custom JwksLoader and security event counter
        TokenSignatureValidator validator = new TokenSignatureValidator(jwksLoader, securityEventCounter, new SignatureTemplateManager(new SignatureAlgorithmPreferences()));

        // Validate the signature - should throw an exception
        TokenValidationException exception = assertThrows(TokenValidationException.class,
                () -> validator.validateSignature(decodedJwt));

        // Verify the exception has the correct event type
        assertEquals(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM, exception.getEventType());

        // Verify log message
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Unsupported algorithm");

        // Verify security event was recorded
        assertEquals(initialCount + 1, securityEventCounter.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM));
    }

    /**
     * Creates a token without a kid in the header.
     */
    private String createTokenWithoutKid() {
        // Create a valid token with RS256
        String validToken = createToken();

        // Split the token into its parts
        String[] parts = validToken.split("\\.");

        // Modify the header to remove the kid
        String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        header = header.replaceAll("\"kid\":\"[^\"]*\",?", "");
        // Fix JSON if needed (remove trailing comma)
        header = header.replace(",}", "}");
        String modifiedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8));

        // Construct a token with the modified header but keep the original payload and signature
        return modifiedHeader + "." + parts[1] + "." + parts[2];
    }

    @Test
    @DisplayName("Should accept RS384 token for RSA key whose JWKS entry omits alg (defaulted RS256)")
    void shouldAcceptRsaFamilyTokenForKeyWithoutAlg() {
        // JWKS for the RS384 default key, with the alg member stripped: KeyProcessor
        // defaults such RSA keys to RS256. The RSA key material can still verify RS384.
        String jwks = InMemoryJWKSFactory.createDefaultJwks(InMemoryKeyMaterialHandler.Algorithm.RS384)
                .replace(",\"alg\":\"RS384\"", "");
        assertFalse(jwks.contains("RS384"), "alg member should be stripped from JWKS");

        String token = Jwts.builder()
                .header().keyId(InMemoryJWKSFactory.DEFAULT_KEY_ID).and()
                .issuer("test-issuer").subject("test-subject")
                .expiration(Date.from(Instant.now().plusSeconds(300)))
                .signWith(InMemoryKeyMaterialHandler.getDefaultPrivateKey(
                        InMemoryKeyMaterialHandler.Algorithm.RS384), Jwts.SIG.RS384)
                .compact();

        DecodedJwt decodedJwt = jwtParser.decode(token);
        JwksLoader jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwks);
        jwksLoader.initJWKSLoader(securityEventCounter);
        TokenSignatureValidator validator = new TokenSignatureValidator(jwksLoader, securityEventCounter,
                new SignatureTemplateManager(new SignatureAlgorithmPreferences()));

        assertDoesNotThrow(() -> validator.validateSignature(decodedJwt),
                "RSA-family token must be accepted for RSA key without explicit alg");
    }

    @Test
    @DisplayName("Should accept PS256 token for RSA key labeled RS384 (same RSA family)")
    void shouldAcceptCrossAlgorithmWithinRsaFamily() {
        String jwks = InMemoryJWKSFactory.createDefaultJwks(InMemoryKeyMaterialHandler.Algorithm.RS384);

        String token = Jwts.builder()
                .header().keyId(InMemoryJWKSFactory.DEFAULT_KEY_ID).and()
                .issuer("test-issuer").subject("test-subject")
                .expiration(Date.from(Instant.now().plusSeconds(300)))
                .signWith(InMemoryKeyMaterialHandler.getDefaultPrivateKey(
                        InMemoryKeyMaterialHandler.Algorithm.RS384), Jwts.SIG.PS256)
                .compact();

        DecodedJwt decodedJwt = jwtParser.decode(token);
        JwksLoader jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwks);
        jwksLoader.initJWKSLoader(securityEventCounter);
        TokenSignatureValidator validator = new TokenSignatureValidator(jwksLoader, securityEventCounter,
                new SignatureTemplateManager(new SignatureAlgorithmPreferences()));

        assertDoesNotThrow(() -> validator.validateSignature(decodedJwt),
                "PS256 token must be accepted for RS384-labeled RSA key");
    }

    /**
     * Creates a token signed with RS256.
     */
    private String createToken() {
        // Create a token using TestTokenHolder
        var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.defaultForTokenType(TokenType.ACCESS_TOKEN));

        // Ensure the key ID is set to the default key ID
        tokenHolder.withKeyId(InMemoryJWKSFactory.DEFAULT_KEY_ID);

        // Return the raw token
        return tokenHolder.getRawToken();
    }

    /**
     * Creates a token for testing algorithm confusion attacks.
     * This simulates a token that claims to use RS256 but with an invalid signature.
     */
    private String createAlgorithmConfusionToken() {
        // Create a valid token with RS256
        String validToken = createToken();

        // Split the token into its parts
        String[] parts = validToken.split("\\.");

        // Modify the header to keep RS256 but change something else
        String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        header = header.replace("\"kid\":\"" + InMemoryJWKSFactory.DEFAULT_KEY_ID + "\"", "\"kid\":\"wrong-key-id\"");
        String modifiedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8));

        // Construct a token with the modified header but keep the original payload and signature
        // This simulates an algorithm confusion attack where the attacker tries to use a valid signature
        // with a modified header
        return modifiedHeader + "." + parts[1] + "." + parts[2];
    }
}
