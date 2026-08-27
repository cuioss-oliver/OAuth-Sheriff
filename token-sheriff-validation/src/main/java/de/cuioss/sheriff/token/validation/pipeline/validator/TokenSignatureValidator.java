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
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.jwks.JwksLoader;
import de.cuioss.sheriff.token.validation.pipeline.DecodedJwt;
import de.cuioss.sheriff.token.validation.pipeline.SignatureTemplateManager;
import de.cuioss.sheriff.token.validation.pipeline.SignatureVerificationUtil;
import de.cuioss.tools.logging.CuiLogger;
import lombok.Getter;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.Set;

/**
 * Validator for JWT Token signatures.
 * <p>
 * This class validates the signature of a JWT Token using a public key
 * retrieved from a configured JwksLoader.
 * <p>
 * It assumes that header validation (algorithm, issuer) has already been
 * performed by {@link TokenHeaderValidator}.
 * <p>
 * This class uses standard JDK cryptographic providers for signature verification, supporting
 * all standard JOSE algorithms as defined in RFC 7518 and RFC 8037:
 * <ul>
 *   <li>RSA signatures: RS256, RS384, RS512</li>
 *   <li>ECDSA signatures: ES256, ES384, ES512</li>
 *   <li>RSA-PSS signatures: PS256, PS384, PS512</li>
 *   <li>EdDSA signatures: EdDSA (Ed25519/Ed448)</li>
 * </ul>
 * <p>
 * All algorithms are supported by the standard JDK cryptographic providers in Java 11+,
 * ensuring excellent compatibility with GraalVM native image compilation and optimal performance.
 * <p>
 * For more details on signature validation, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#token-validation-pipeline">Token Validation Pipeline</a>
 * and <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/security-reference.adoc">Security Specification</a>
 *
 * @apiNote This class is internal to Token-Sheriff and not part of the public API.
 * @since 1.0
 * @author Oliver Wolff
 */
public class TokenSignatureValidator {

    private static final CuiLogger LOGGER = new CuiLogger(TokenSignatureValidator.class);

    @Getter
    private final JwksLoader jwksLoader;


    private final SecurityEventCounter securityEventCounter;


    private final SignatureTemplateManager signatureTemplateManager;

    /**
     * Constructs a TokenSignatureValidator with the specified JwksLoader, SecurityEventCounter,
     * and shared SignatureTemplateManager.
     *
     * @param jwksLoader               the JWKS loader to use for key retrieval
     * @param securityEventCounter     the counter for security events
     * @param signatureTemplateManager shared signature template manager (reused across validators for the same issuer)
     */
    public TokenSignatureValidator(JwksLoader jwksLoader,
            SecurityEventCounter securityEventCounter,
            SignatureTemplateManager signatureTemplateManager) {
        this.jwksLoader = jwksLoader;
        this.securityEventCounter = securityEventCounter;
        this.signatureTemplateManager = signatureTemplateManager;
    }

    /**
     * Validates the signature of a decoded JWT Token.
     * <p>
     * <strong>Preconditions:</strong> This validator assumes that the following have already been validated:
     * <ul>
     *   <li>Token format (3 parts: header.payload.signature)</li>
     *   <li>Algorithm (alg) claim presence and support  </li>
     *   <li>Header structure and basic JWT format</li>
     * </ul>
     * <p>
     * This validator is responsible for:
     * <ul>
     *   <li>Key ID (kid) claim presence validation</li>
     *   <li>Key retrieval from JWKS</li>
     *   <li>Algorithm compatibility between token and key</li>
     *   <li>Cryptographic signature verification</li>
     * </ul>
     *
     * @param decodedJwt the decoded JWT Token to validate
     * @throws TokenValidationException if the signature is invalid
     */
    @SuppressWarnings("java:S3655") // owolff: False Positive: isPresent is checked before calling get()
    public void validateSignature(DecodedJwt decodedJwt) {
        LOGGER.debug("Validating validation signature");

        // Get the kid from the validation header - precondition: already validated by TokenHeaderValidator
        var kid = decodedJwt.getKid().orElseThrow(() ->
                new IllegalStateException("Key ID (kid) should have been validated by TokenHeaderValidator"));

        // Get the algorithm from the validation header - precondition: already validated by TokenHeaderValidator
        var algorithm = decodedJwt.getAlg().orElseThrow(() ->
                new IllegalStateException("Algorithm (alg) should have been validated by TokenHeaderValidator"));

        // Signature validation is performed in verifySignature method

        // Get the key from the JwksLoader
        var keyInfo = jwksLoader.getKeyInfo(kid);
        if (keyInfo.isEmpty()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.KEY_NOT_FOUND, kid);
            securityEventCounter.increment(SecurityEventCounter.EventType.KEY_NOT_FOUND);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.KEY_NOT_FOUND,
                    "Key not found for key ID: %s. Please verify the key exists in the JWKS endpoint or configuration.".formatted(kid)
            );
        }

        // Verify that the key's algorithm matches the validation's algorithm
        if (!isAlgorithmCompatible(algorithm, keyInfo.get().algorithm())) {
            LOGGER.warn(JWTValidationLogMessages.WARN.UNSUPPORTED_ALGORITHM, algorithm);
            securityEventCounter.increment(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM,
                    "Algorithm not compatible with key: %s is not compatible with %s".formatted(algorithm, keyInfo.get().algorithm())
            );
        }

        // Verify the signature
        try {
            LOGGER.debug("All checks passed, verifying signature");
            verifySignature(decodedJwt, keyInfo.get().key(), algorithm);
        } catch (IllegalArgumentException e) {
            LOGGER.warn(e, JWTValidationLogMessages.ERROR.SIGNATURE_VALIDATION_FAILED, e.getMessage());
            securityEventCounter.increment(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED,
                    "Signature validation failed: %s".formatted(e.getMessage()),
                    e
            );
        }
    }

    /**
     * Verifies the signature of a JWT Token using the provided public key and algorithm.
     *
     * @param decodedJwt the decoded JWT Token
     * @param publicKey  the public key to use for verification
     * @param algorithm  the algorithm to use for verification
     * @throws TokenValidationException if the signature is invalid
     */
    private void verifySignature(DecodedJwt decodedJwt, PublicKey publicKey, String algorithm) {
        LOGGER.trace("Verifying signature:\nDecodedJwt: %s\nPublicKey: %s\nAlgorithm: %s", decodedJwt, publicKey, algorithm);

        // Get the data to verify and signature bytes from DecodedJwt
        String dataToVerify;
        byte[] signatureBytes;
        try {
            dataToVerify = decodedJwt.getDataToVerify();
            signatureBytes = decodedJwt.getSignatureAsDecodedBytes();
        } catch (IllegalStateException e) {
            LOGGER.warn(e, JWTValidationLogMessages.ERROR.SIGNATURE_VALIDATION_FAILED, e.getMessage());
            securityEventCounter.increment(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED,
                    "Failed to extract JWT data for signature verification: %s".formatted(e.getMessage()),
                    e
            );
        }

        byte[] dataBytes = dataToVerify.getBytes(StandardCharsets.UTF_8);

        // H3: explicitly reject out-of-range ECDSA signature components (r == 0, s == 0, or r,s >= n)
        // before verification. This keeps the "psychic signature" defense (CVE-2022-21449) in our own
        // code rather than relying solely on the JDK provider to reject a degenerate (0,0) signature.
        if (algorithm.startsWith("ES") && publicKey instanceof ECPublicKey ecPublicKey) {
            checkEcdsaComponentRange(signatureBytes, ecPublicKey);
        }

        // Verify signature using shared utility (handles ECDSA format conversion)
        try {
            boolean isValid = SignatureVerificationUtil.verifySignature(
                    signatureTemplateManager, publicKey, algorithm, dataBytes, signatureBytes);
            if (isValid) {
                LOGGER.debug("Signature is valid");
            } else {
                LOGGER.warn(JWTValidationLogMessages.ERROR.SIGNATURE_VALIDATION_FAILED, "Invalid signature");
                securityEventCounter.increment(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED);
                throw new TokenValidationException(
                        SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED,
                        "Invalid signature"
                );
            }
        } catch (InvalidKeyException | SignatureException e) {
            LOGGER.warn(e, JWTValidationLogMessages.ERROR.SIGNATURE_VALIDATION_FAILED, e.getMessage());
            securityEventCounter.increment(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED,
                    "Signature validation failed: %s".formatted(e.getMessage()),
                    e
            );
        } catch (SignatureTemplateManager.UnsupportedAlgorithmException e) {
            LOGGER.warn(e, JWTValidationLogMessages.ERROR.SIGNATURE_VALIDATION_FAILED, e.getMessage());
            securityEventCounter.increment(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM);
            throw new TokenValidationException(
                    SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM,
                    "Algorithm not supported: %s".formatted(e.getMessage()),
                    e
            );
        }
    }

    /**
     * Rejects an ECDSA signature whose {@code r} or {@code s} component is out of range (H3).
     * <p>
     * A JWS ECDSA signature is the fixed-width concatenation {@code r || s} (RFC 7515). A valid
     * signature requires {@code 0 < r < n} and {@code 0 < s < n}, where {@code n} is the curve
     * order. The all-zero {@code (0, 0)} signature at the heart of the "psychic signature" attack
     * (CVE-2022-21449) violates this and is rejected here before it reaches the platform verifier.
     *
     * @param signatureBytes the raw JWS ECDSA signature ({@code r || s})
     * @param publicKey      the EC public key, used to obtain the curve order {@code n}
     * @throws TokenValidationException if a component is zero, negative, or not less than {@code n}
     */
    private void checkEcdsaComponentRange(byte[] signatureBytes, ECPublicKey publicKey) {
        if (signatureBytes.length == 0 || signatureBytes.length % 2 != 0) {
            rejectSignature("Malformed ECDSA signature: expected an even-length r||s encoding");
            return; // defensive: do not proceed if rejectSignature is ever refactored to not throw
        }
        int componentLength = signatureBytes.length / 2;
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(signatureBytes, 0, componentLength));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signatureBytes, componentLength, signatureBytes.length));
        ECParameterSpec params = publicKey.getParams();
        if (params == null) {
            rejectSignature("Invalid EC public key: missing domain parameters");
            return; // defensive: do not dereference null domain parameters below
        }
        BigInteger n = params.getOrder();
        if (r.signum() <= 0 || s.signum() <= 0 || r.compareTo(n) >= 0 || s.compareTo(n) >= 0) {
            rejectSignature("ECDSA signature component out of range: r and s must satisfy 0 < r,s < n");
        }
    }

    /**
     * Logs, counts, and throws a {@link TokenValidationException} for an invalid signature.
     *
     * @param message the human-readable rejection reason
     * @throws TokenValidationException always
     */
    private void rejectSignature(String message) {
        LOGGER.warn(JWTValidationLogMessages.ERROR.SIGNATURE_VALIDATION_FAILED, message);
        securityEventCounter.increment(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED);
        throw new TokenValidationException(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED, message);
    }

    /**
     * The JWA signature algorithms of the RSA family (RSASSA-PKCS1-v1_5 and RSASSA-PSS).
     * An RSA public key can verify signatures of any of these algorithms.
     */
    private static final Set<String> RSA_FAMILY_ALGORITHMS =
            Set.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512");

    /**
     * Checks if the token's signature algorithm is compatible with the key's algorithm.
     * <p>
     * Both parameters are JWA algorithm identifiers (e.g. "RS256", "ES384", "EdDSA") —
     * {@code KeyProcessor} always assigns a JWA identifier to loaded keys (defaulting to
     * "RS256" for RSA keys without an {@code alg} field and deriving ES* from the curve
     * for EC keys).
     * <p>
     * Compatibility rules:
     * <ul>
     *   <li><strong>RSA family (RS* and PS*):</strong> The {@code alg} member of a JWK is advisory
     *       (RFC 7517, Section 4.4); the RSA key material can verify any RS* or PS* signature.
     *       Therefore any RSA-family token algorithm is accepted for an RSA-family key.</li>
     *   <li><strong>EC (ES*):</strong> The curve binds the key to exactly one ES variant
     *       (P-256 → ES256, P-384 → ES384, P-521 → ES512), so an exact match is required.</li>
     *   <li><strong>EdDSA:</strong> Single identifier, exact match.</li>
     *   <li><strong>Anything else:</strong> Exact match.</li>
     * </ul>
     *
     * @param tokenAlgorithm the JWA algorithm from the validation header
     * @param keyAlgorithm   the JWA algorithm associated with the key
     * @return true if the algorithms are compatible, false otherwise
     */
    private boolean isAlgorithmCompatible(String tokenAlgorithm, String keyAlgorithm) {
        if (tokenAlgorithm == null || keyAlgorithm == null) {
            return false;
        }
        if (RSA_FAMILY_ALGORITHMS.contains(keyAlgorithm)) {
            return RSA_FAMILY_ALGORITHMS.contains(tokenAlgorithm);
        }
        // EC (curve-bound), EdDSA, and all other algorithms require an exact match
        return tokenAlgorithm.equals(keyAlgorithm);
    }
}
