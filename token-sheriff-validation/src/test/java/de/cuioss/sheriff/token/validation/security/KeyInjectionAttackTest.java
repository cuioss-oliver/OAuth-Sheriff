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
package de.cuioss.sheriff.token.validation.security;

import com.dslplatform.json.DslJson;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.JwkKey;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.dpop.DpopConfig;
import de.cuioss.sheriff.token.validation.dpop.DpopProofValidator;
import de.cuioss.sheriff.token.validation.dpop.DpopReplayProtection;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.json.JwtHeader;
import de.cuioss.sheriff.token.validation.json.MapRepresentation;
import de.cuioss.sheriff.token.validation.jwks.key.KeyInfo;
import de.cuioss.sheriff.token.validation.jwks.parser.KeyProcessor;
import de.cuioss.sheriff.token.validation.pipeline.DecodedJwt;
import de.cuioss.sheriff.token.validation.pipeline.SignatureTemplateManager;
import de.cuioss.sheriff.token.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.sheriff.token.validation.test.TestTokenHolder;
import de.cuioss.sheriff.token.validation.test.generator.TestTokenGenerators;
import de.cuioss.sheriff.token.validation.test.junit.TestTokenSource;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for KID injection vulnerabilities.
 * <p>
 * These tests verify that the library correctly rejects tokens with malicious
 * KID (Key ID) headers that attempt to exploit path traversal, SQL injection,
 * or other injection techniques.
 * <p>
 * What is tested:
 * <ul>
 *   <li>Path traversal via KID header</li>
 *   <li>SQL injection via KID header</li>
 *   <li>Null byte injection via KID header</li>
 *   <li>Other key injection techniques</li>
 * </ul>
 * <p>
 * Why it's important:
 * <p>
 * The KID header in a JWT token is used to identify which key should be used to
 * verify the token's signature. If this value is not properly validated and sanitized,
 * attackers can manipulate it to perform various attacks:
 * <ul>
 *   <li>Path traversal to read arbitrary files on the server</li>
 *   <li>SQL injection to extract data or bypass authentication</li>
 *   <li>Command injection to execute arbitrary commands</li>
 * </ul>
 * <p>
 * How testing is performed:
 * <p>
 * Testing involves creating tokens with various malicious KID values and verifying
 * that the library rejects them with appropriate error messages and increments
 * security event counters.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("KID Injection Attack Tests")
class KeyInjectionAttackTest {

    private static final CuiLogger LOGGER = new CuiLogger(KeyInjectionAttackTest.class);

    private static final String TEST_ISSUER = "https://test-issuer.example.com";

    private TokenValidator tokenValidator;
    private DpopProofValidator dpopValidator;
    private DpopReplayProtection replayProtection;

    @BeforeEach
    void setUp() {

        // Create a valid token
        TestTokenHolder validToken = TestTokenGenerators.accessTokens().next();

        // Get the issuer config from the token
        IssuerConfig issuerConfig = validToken.getIssuerConfig();
        // Create the token validator
        ParserConfig config = ParserConfig.builder().build();
        tokenValidator = TokenValidator.builder().parserConfig(config).issuerConfig(issuerConfig).build();

        // Set up a DPoP proof validator for the embedded-JWK weak-key test
        replayProtection = new DpopReplayProtection(300, 10_000);
        IssuerConfig dpopIssuerConfig = IssuerConfig.builder()
                .issuerIdentifier(TEST_ISSUER)
                .dpopConfig(DpopConfig.builder().build())
                .jwksContent(InMemoryKeyMaterialHandler.createDefaultJwks())
                .audienceValidationDisabled(true)
                .build();
        dpopValidator = new DpopProofValidator(dpopIssuerConfig, new SecurityEventCounter(), replayProtection,
                new SignatureTemplateManager(dpopIssuerConfig.getAlgorithmPreferences()),
                ParserConfig.builder().build(), new DslJson<>(new DslJson.Settings<>()));
    }

    @AfterEach
    void tearDown() {
        if (replayProtection != null) {
            replayProtection.close();
        }
    }

    /**
     * Creates a token with a malicious KID header by modifying the header of a valid token.
     *
     * @param maliciousKid the malicious KID value to inject
     * @return a JWT token string with the malicious KID header
     */
    private String createTokenWithMaliciousKid(String maliciousKid) {
        // Create a new token with the malicious kid
        // This approach is more reliable than trying to modify an existing token

        // Get a new token holder
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();

        // Set the malicious kid
        tokenHolder.withKeyId(maliciousKid);

        // Get the raw token
        return tokenHolder.getRawToken();
    }

    /**
     * Provides test cases for KID injection attacks.
     * Each test case consists of:
     * - A malicious KID value
     * - A display name for the test
     * - The expected security event type
     * - Whether to check for "Key not found" in the error message
     *
     * @return a stream of test cases
     */
    static Stream<Arguments> kidInjectionTestCases() {
        return Stream.of(
                // Path traversal attack
                Arguments.of(
                        "../../../etc/passwd",
                        "path traversal",
                        SecurityEventCounter.EventType.KEY_NOT_FOUND,
                        true
                ),
                // SQL injection attack
                Arguments.of(
                        "' OR 1=1 --",
                        "SQL injection",
                        SecurityEventCounter.EventType.KEY_NOT_FOUND,
                        true
                ),
                // Null byte injection attack
                Arguments.of(
                        "valid-key-id\0malicious-suffix",
                        "null byte injection",
                        SecurityEventCounter.EventType.KEY_NOT_FOUND,
                        false
                ),
                // Command injection attack
                Arguments.of(
                        "$(rm -rf /tmp/*)",
                        "command injection",
                        SecurityEventCounter.EventType.KEY_NOT_FOUND,
                        true
                ),
                // Very long KID (potential DoS attack)
                Arguments.of(
                        "a".repeat(10000),
                        "very long",
                        SecurityEventCounter.EventType.TOKEN_SIZE_EXCEEDED,
                        false
                )
        );
    }

    /**
     * Parameterized test for various KID injection attacks.
     * This test verifies that tokens with malicious KID headers are properly rejected.
     *
     * @param maliciousKid the malicious KID value to inject
     * @param attackType a description of the attack type for logging
     * @param expectedEventType the expected security event type
     * @param checkKeyNotFoundMessage whether to check for "Key not found" in the error message
     */
    @ParameterizedTest(name = "Should reject token with {1} in KID header")
    @MethodSource("kidInjectionTestCases")
    void shouldRejectTokenWithMaliciousKidHeader(String maliciousKid, String attackType,
            SecurityEventCounter.EventType expectedEventType,
            boolean checkKeyNotFoundMessage) {
        // Create a token with the malicious KID
        String token = createTokenWithMaliciousKid(maliciousKid);

        LOGGER.debug("Created token with %s KID: %s", attackType, token);

        // Reset the security event counter for this test
        tokenValidator.getSecurityEventCounter().reset();

        // Verify that the token is rejected
        var kidRequest = AccessTokenRequest.of(token);
        var exception = assertThrows(TokenValidationException.class,
                () -> tokenValidator.createAccessToken(kidRequest));

        // Verify the error message if needed
        LOGGER.debug("Exception message: %s", exception.getMessage());
        if (checkKeyNotFoundMessage) {
            assertTrue(exception.getMessage().contains("Key not found"),
                    "Error message should indicate key not found");
        }

        // Verify that the security event counter is incremented
        assertEquals(1, tokenValidator.getSecurityEventCounter().getCount(expectedEventType),
                "Security event counter should be incremented for " + expectedEventType);
    }

    @ParameterizedTest
    @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 3)
    @DisplayName("Should accept token with valid KID header")
    void shouldAcceptTokenWithValidKidHeader(TestTokenHolder tokenHolder) {
        String token = tokenHolder.getRawToken();

        LOGGER.debug("Using valid token: %s", token);

        var accessToken = tokenValidator.createAccessToken(AccessTokenRequest.of(token));
        assertNotNull(accessToken, "Token with valid KID should be accepted");
        assertEquals(0, tokenValidator.getSecurityEventCounter().getCount(SecurityEventCounter.EventType.KEY_NOT_FOUND),
                "No KEY_NOT_FOUND security events should be recorded for valid token");
    }

    @ParameterizedTest(name = "Should reject {0}-bit RSA key on the JWKS parsing path")
    @ValueSource(ints = {512, 1024})
    @DisplayName("Should reject sub-2048-bit RSA keys on the JWKS path (M1)")
    void shouldRejectWeakRsaKeyOnJwksPath(int bits) throws Exception {
        RSAPublicKey weakKey = generateRsaPublicKey(bits);
        JwkKey jwk = rsaJwkKey(weakKey, "weak-rsa-kid");
        SecurityEventCounter counter = new SecurityEventCounter();
        KeyProcessor processor = new KeyProcessor(counter, new JwkAlgorithmPreferences());

        Optional<KeyInfo> result = processor.processKey(jwk);

        assertTrue(result.isEmpty(), bits + "-bit RSA key must be rejected on the JWKS path");
        assertEquals(1, counter.getCount(SecurityEventCounter.EventType.JWKS_JSON_PARSE_FAILED),
                "A sub-2048-bit RSA key must increment the JWKS parse-failed counter");
    }

    @Test
    @DisplayName("Should still accept a conformant 2048-bit RSA key on the JWKS path (M1)")
    void shouldAcceptConformantRsaKeyOnJwksPath() throws Exception {
        RSAPublicKey strongKey = generateRsaPublicKey(2048);
        JwkKey jwk = rsaJwkKey(strongKey, "strong-rsa-kid");
        SecurityEventCounter counter = new SecurityEventCounter();
        KeyProcessor processor = new KeyProcessor(counter, new JwkAlgorithmPreferences());

        Optional<KeyInfo> result = processor.processKey(jwk);

        assertTrue(result.isPresent(), "A conformant 2048-bit RSA key must still be accepted");
        assertEquals(0, counter.getCount(SecurityEventCounter.EventType.JWKS_JSON_PARSE_FAILED),
                "A conformant RSA key must not increment the JWKS parse-failed counter");
    }

    @Test
    @DisplayName("Should reject a DPoP proof whose embedded JWK is a weak (1024-bit) RSA key (M1)")
    void shouldRejectWeakRsaKeyOnDpopEmbeddedJwkPath() throws Exception {
        RSAPublicKey weakKey = generateRsaPublicKey(1024);
        String modulus = base64Url(weakKey.getModulus());
        String exponent = base64Url(weakKey.getPublicExponent());

        // Build a DPoP proof carrying the weak RSA key as its embedded JWK. The signature is a
        // placeholder: the embedded key is rejected during key parsing, before signature verification.
        String headerJson = ("{\"typ\":\"dpop+jwt\",\"alg\":\"RS256\",\"jwk\":{\"kty\":\"RSA\",\"kid\":\"weak\","
                + "\"n\":\"%s\",\"e\":\"%s\"}}").formatted(modulus, exponent);
        String bodyJson = "{\"jti\":\"weak-rsa-jti\",\"iat\":%d,\"ath\":\"test-ath\"}"
                .formatted(System.currentTimeMillis() / 1000);
        String proof = base64Url(headerJson.getBytes(StandardCharsets.UTF_8)) + "."
                + base64Url(bodyJson.getBytes(StandardCharsets.UTF_8)) + ".dummy-sig";

        AccessTokenRequest request = AccessTokenRequest.of("dummy-token", Map.of("dpop", List.of(proof)));
        DecodedJwt accessToken = createAccessTokenJwt("any-thumbprint");

        var exception = assertThrows(TokenValidationException.class,
                () -> dpopValidator.validate(request, accessToken, "dummy-token"),
                "A DPoP proof with a sub-2048-bit embedded RSA key must be rejected");
        assertEquals(SecurityEventCounter.EventType.DPOP_PROOF_INVALID, exception.getEventType(),
                "A weak embedded RSA key must be rejected as an invalid DPoP proof");
        assertTrue(exception.getMessage().contains("minimum accepted is 2048"),
                "The rejection must be driven by the embedded key's sub-2048-bit size, but was: "
                        + exception.getMessage());
    }

    private static RSAPublicKey generateRsaPublicKey(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        KeyPair keyPair = generator.generateKeyPair();
        return (RSAPublicKey) keyPair.getPublic();
    }

    private static JwkKey rsaJwkKey(RSAPublicKey publicKey, String kid) {
        return new JwkKey("RSA", kid, "RS256",
                base64Url(publicKey.getModulus()), base64Url(publicKey.getPublicExponent()),
                null, null, null);
    }

    private static String base64Url(BigInteger value) {
        return base64Url(toUnsignedBytes(value));
    }

    private static String base64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static byte[] toUnsignedBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    private static DecodedJwt createAccessTokenJwt(String cnfJkt) {
        Map<String, Object> bodyMap = new HashMap<>();
        bodyMap.put("iss", TEST_ISSUER);
        bodyMap.put("sub", "test-subject");
        bodyMap.put("exp", (System.currentTimeMillis() / 1000) + 3600);
        bodyMap.put("iat", System.currentTimeMillis() / 1000);
        if (cnfJkt != null) {
            bodyMap.put("cnf", Map.of("jkt", cnfJkt));
        }

        var body = new MapRepresentation(bodyMap);
        var header = new JwtHeader("RS256", null, "test-key-id", null, null, null, null, null, null, null);
        return new DecodedJwt(header, body, "dummy-sig", new String[]{"a", "b", "c"}, "a.b.c");
    }
}
