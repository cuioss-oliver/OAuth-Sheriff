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

import de.cuioss.sheriff.token.validation.util.EcdsaSignatureFormatConverter;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Shared utility for cryptographic signature verification, used by both
 * {@code TokenSignatureValidator} (JWT access/ID tokens) and {@code DpopProofValidator} (DPoP proofs).
 * <p>
 * Centralizes the ECDSA detection and IEEE P1363 → ASN.1/DER format conversion logic
 * to prevent divergence between the two verification paths.
 *
 * @since 1.0
 */
public final class SignatureVerificationUtil {

    private SignatureVerificationUtil() {
        // utility class
    }

    /**
     * Checks if the algorithm is an ECDSA algorithm that requires signature format conversion
     * from IEEE P1363 (used by JWS/JWT) to ASN.1/DER (used by JCA).
     *
     * @param algorithm the JWT signature algorithm (e.g., "ES256", "RS256")
     * @return true if the algorithm is ECDSA (ES256, ES384, ES512), false otherwise
     */
    public static boolean isEcdsaAlgorithm(String algorithm) {
        return "ES256".equals(algorithm) || "ES384".equals(algorithm) || "ES512".equals(algorithm);
    }

    /**
     * Verifies a signature using the provided public key and algorithm.
     * Handles ECDSA signature format conversion automatically.
     *
     * @param signatureTemplateManager the manager providing pre-configured Signature instances
     * @param publicKey                the public key for verification
     * @param algorithm                the JWT algorithm name (e.g., "ES256", "RS256")
     * @param dataBytes                the data that was signed (header.payload as UTF-8 bytes)
     * @param signatureBytes           the raw signature bytes (Base64url-decoded)
     * @return true if the signature is valid, false otherwise
     * @throws InvalidKeyException                                    if the key is invalid for this algorithm
     * @throws SignatureException                                     if the signature verification process fails
     * @throws SignatureTemplateManager.UnsupportedAlgorithmException if the algorithm is not supported
     */
    public static boolean verifySignature(SignatureTemplateManager signatureTemplateManager,
            PublicKey publicKey, String algorithm, byte[] dataBytes, byte[] signatureBytes)
            throws InvalidKeyException, SignatureException {
        Signature verifier = signatureTemplateManager.getSignatureInstance(algorithm);
        verifier.initVerify(publicKey);
        verifier.update(dataBytes);

        // Convert ECDSA signatures from IEEE P1363 to ASN.1/DER format if needed
        byte[] verificationSignature = signatureBytes;
        if (isEcdsaAlgorithm(algorithm)) {
            verificationSignature = EcdsaSignatureFormatConverter.toJCACompatibleSignature(signatureBytes, algorithm);
        }

        return verifier.verify(verificationSignature);
    }
}
