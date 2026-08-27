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

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.tools.logging.CuiLogger;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

/**
 * Utility class for tampering with JWT tokens for testing purposes.
 * Provides methods to apply different tampering strategies to tokens.
 */
public class JwtTokenTamperingUtil {

    private static final CuiLogger LOGGER = new CuiLogger(JwtTokenTamperingUtil.class);

    /**
     * Generator for replacement characters.
     */
    private static final TypedGenerator<Character> CHAR_GENERATOR_A_B = Generators.fixedValues(List.of('A', 'B'));

    /**
     * Generator for replacement characters.
     */
    private static final TypedGenerator<Character> CHAR_GENERATOR_C_D = Generators.fixedValues(List.of('C', 'D'));

    /**
     * Generator for replacement characters.
     */
    private static final TypedGenerator<Character> CHAR_GENERATOR_X_Y = Generators.fixedValues(List.of('X', 'Y'));

    /**
     * Maximum number of attempts to generate a different character.
     */
    private static final int MAX_ATTEMPTS = 10;

    /**
     * Generates a character that is different from the original character.
     *
     * @param originalChar the character to be replaced
     * @param generator the generator to use for generating characters
     * @return a different character
     */
    private static char generateDifferentChar(char originalChar, TypedGenerator<Character> generator) {
        char newChar;
        int attempts = 0;

        do {
            newChar = generator.next();
            attempts++;
        } while (newChar == originalChar && attempts < MAX_ATTEMPTS);

        // Fallback: if the generator didn't produce a different character,
        // use deterministic replacement
        if (newChar == originalChar) {
            newChar = deterministicDifferentChar(originalChar);
        }

        return newChar;
    }

    /**
     * Deterministically produces a different valid base64url character.
     * Unlike the generator-based approach, this always succeeds because it uses
     * a wide range of replacement characters.
     *
     * @param original the character to replace
     * @return a character that is guaranteed to be different from the original
     */
    private static char deterministicDifferentChar(char original) {
        if (original >= 'A' && original <= 'Z') {
            return 'a'; // always different from any uppercase letter
        } else if (original >= 'a' && original <= 'z') {
            return 'A'; // always different from any lowercase letter
        } else if (Character.isDigit(original)) {
            return 'A';
        } else if (original == '-') {
            return '_';
        } else if (original == '_') {
            return '-';
        } else {
            return 'A';
        }
    }

    /**
     * Enum defining different tampering strategies for JWT tokens.
     */
    @Getter
    @RequiredArgsConstructor
    public enum TamperingStrategy {
        /**
         * Modifies the last character of the signature.
         */
        MODIFY_SIGNATURE_LAST_CHAR("Modify the last character of the signature"),

        /**
         * Modifies a random character in the signature.
         */
        MODIFY_SIGNATURE_RANDOM_CHAR("Modify a random character in the signature"),

        /**
         * Removes the signature entirely.
         */
        REMOVE_SIGNATURE("Remove the signature entirely"),

        /**
         * Changes the algorithm in the header to 'none'.
         */
        ALGORITHM_NONE("Change algorithm to 'none'"),

        /**
         * Changes the algorithm in the header from RS256 to HS256 (algorithm downgrade).
         */
        ALGORITHM_DOWNGRADE("Change algorithm from RS256 to HS256"),

        /**
         * Uses a completely different signature.
         */
        DIFFERENT_SIGNATURE("Use a completely different signature"),

        /**
         * Changes the key ID (kid) in the header to an invalid value.
         */
        INVALID_KID("Change key ID to an invalid value"),

        /**
         * Removes the key ID (kid) from the header.
         */
        REMOVE_KID("Remove key ID from header");

        private final String description;
    }

    /**
     * Generator for tampering strategies.
     */
    public static final TypedGenerator<TamperingStrategy> STRATEGIES = Generators.enumValues(TamperingStrategy.class);

    /**
     * Shorthand for tampering a given validation
     */
    public static String tamperWithToken(@NonNull String token) {
        TamperingStrategy next = STRATEGIES.next();
        LOGGER.info("Apply strategy '%s' to validation '%s'", next, token);
        return applyTamperingStrategy(token, next);
    }

    /**
     * Applies a tampering strategy to a JWT Token.
     *
     * @param token    the original JWT Token
     * @param strategy the tampering strategy to apply
     * @return the tampered validation
     */
    public static String applyTamperingStrategy(String token, TamperingStrategy strategy) {
        Objects.requireNonNull(token, "Token must not be null");
        Objects.requireNonNull(strategy, "Strategy must not be null");

        return switch (strategy) {
            case MODIFY_SIGNATURE_LAST_CHAR -> modifySignatureLastChar(token);
            case MODIFY_SIGNATURE_RANDOM_CHAR -> modifySignatureRandomChar(token);
            case REMOVE_SIGNATURE -> removeSignature(token);
            case ALGORITHM_NONE -> changeAlgorithmToNone(token);
            case ALGORITHM_DOWNGRADE -> downgradeAlgorithm(token);
            case DIFFERENT_SIGNATURE -> useDifferentSignature(token);
            case INVALID_KID -> changeKeyIdToInvalid(token);
            case REMOVE_KID -> removeKeyId(token);
        };
    }

    /**
     * Modifies the last character of the signature.
     *
     * @param token the original JWT Token
     * @return the tampered validation
     */
    private static String modifySignatureLastChar(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return token; // Not a valid JWT Token
        }

        String signature = parts[2];
        if (signature.isEmpty()) {
            return token;
        }

        // Ensure we make a significant change to the signature
        // Instead of just changing the last character, we'll modify multiple characters
        // or use a completely different approach if the signature is very short
        if (signature.length() <= 2) {
            // For very short signatures, use a completely different approach
            return useDifferentSignature(token);
        } else if (signature.length() <= 5) {
            // For short signatures, modify the last two characters
            char lastChar = signature.charAt(signature.length() - 1);
            char secondLastChar = signature.charAt(signature.length() - 2);
            char newLastChar = generateDifferentChar(lastChar, CHAR_GENERATOR_A_B);
            char newSecondLastChar = generateDifferentChar(secondLastChar, CHAR_GENERATOR_C_D);
            String tamperedSignature = signature.substring(0, signature.length() - 2)
                    + newSecondLastChar + newLastChar;
            return parts[0] + "." + parts[1] + "." + tamperedSignature;
        } else {
            // For longer signatures, modify the second-to-last character and a character
            // in the middle. We avoid the last character because in base64url encoding,
            // the last character may have padding bits that don't affect the decoded bytes
            // (e.g., for RS256 with 256 bytes, the last char has 4 padding bits).
            int endIndex = signature.length() - 2;
            int middleIndex = signature.length() / 2;
            char endChar = signature.charAt(endIndex);
            char middleChar = signature.charAt(middleIndex);

            char newEndChar = generateDifferentChar(endChar, CHAR_GENERATOR_A_B);
            char newMiddleChar = generateDifferentChar(middleChar, CHAR_GENERATOR_X_Y);

            StringBuilder tamperedSignature = new StringBuilder(signature);
            tamperedSignature.setCharAt(middleIndex, newMiddleChar);
            tamperedSignature.setCharAt(endIndex, newEndChar);

            LOGGER.debug("Original signature: %s, Tampered signature: %s", signature, tamperedSignature);
            return parts[0] + "." + parts[1] + "." + tamperedSignature;
        }
    }

    /**
     * Modifies a random character in the signature part of the validation.
     *
     * @param token the original JWT Token
     * @return the tampered validation
     */
    private static String modifySignatureRandomChar(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return token; // Not a valid JWT Token
        }

        String signature = parts[2];
        if (signature.isEmpty()) {
            return token;
        }

        // For base64url, we need to ensure we modify a character that will actually
        // change the decoded bytes. The last character in base64url might only
        // contribute 2 bits when the signature length is certain values.
        // To ensure tampering always changes the decoded bytes, we avoid the last character
        // and pick from the rest of the signature.

        int maxIndex = signature.length() - 1;
        // If signature is long enough, avoid the last character to ensure we change decoded bytes
        if (signature.length() > 4) {
            maxIndex = signature.length() - 2;
        }

        int randomIndex = Generators.integers(0, maxIndex).next();
        char originalChar = signature.charAt(randomIndex);

        // Use a character that will definitely change the decoded value
        // We need to ensure the new character differs in more than just the trailing bits
        char newChar;
        if (Character.isDigit(originalChar)) {
            // If it's a digit, change to a letter
            newChar = CHAR_GENERATOR_A_B.next();
        } else if (originalChar >= 'A' && originalChar <= 'Z') {
            // If uppercase, change to lowercase or digit
            newChar = originalChar == 'A' ? 'z' : 'a';
        } else if (originalChar >= 'a' && originalChar <= 'z') {
            // If lowercase, change to uppercase or digit
            newChar = originalChar == 'a' ? 'Z' : 'A';
        } else if (originalChar == '-') {
            newChar = '_';
        } else if (originalChar == '_') {
            newChar = '-';
        } else {
            // Default: use the generator but ensure it's different
            newChar = generateDifferentChar(originalChar, CHAR_GENERATOR_X_Y);
        }

        String tamperedSignature = signature.substring(0, randomIndex) + newChar +
                (randomIndex < signature.length() - 1 ? signature.substring(randomIndex + 1) : "");

        return parts[0] + "." + parts[1] + "." + tamperedSignature;
    }

    /**
     * Removes the signature entirely.
     *
     * @param token the original JWT Token
     * @return the tampered validation
     */
    private static String removeSignature(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return token; // Not a valid JWT Token
        }
        return parts[0] + "." + parts[1] + ".";
    }

    /**
     * Changes the algorithm in the header to 'none'.
     *
     * @param token the original JWT Token
     * @return the tampered validation
     */
    private static String changeAlgorithmToNone(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return token; // Not a valid JWT Token
        }

        try {
            // Decode the header
            String decodedHeader = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            // Replace the algorithm with "none"
            String modifiedHeader = decodedHeader.replaceAll("\"alg\"\\s*:\\s*\"[^\"]*\"", "\"alg\":\"none\"");
            // Encode the modified header
            String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(modifiedHeader.getBytes(StandardCharsets.UTF_8));

            // Return the modified validation
            return encodedHeader + "." + parts[1] + "." + parts[2];
        } catch (IllegalArgumentException | IllegalStateException e) {
            return token; // In case of any error, return the original validation
        }
    }

    /**
     * Changes the algorithm in the header from RS256 to HS256 (algorithm downgrade).
     *
     * @param token the original JWT Token
     * @return the tampered validation
     */
    private static String downgradeAlgorithm(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return token; // Not a valid JWT Token
        }

        try {
            // Decode the header
            String decodedHeader = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            // Replace RS256 with HS256
            String modifiedHeader = decodedHeader.replaceAll("\"alg\"\\s*:\\s*\"RS256\"", "\"alg\":\"HS256\"");
            // Encode the modified header
            String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(modifiedHeader.getBytes(StandardCharsets.UTF_8));

            // Return the modified validation
            return encodedHeader + "." + parts[1] + "." + parts[2];
        } catch (IllegalArgumentException | IllegalStateException e) {
            return token; // In case of any error, return the original validation
        }
    }

    /**
     * Uses a completely different signature.
     *
     * @param token the original JWT Token
     * @return the tampered validation
     */
    private static String useDifferentSignature(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return token; // Not a valid JWT Token
        }

        try {
            // Create a completely different signature
            // We'll just reverse the original signature to make it invalid
            String originalSignature = parts[2];
            StringBuilder reversedSignature = new StringBuilder(originalSignature).reverse();

            // If the reversed signature is the same as the original (e.g., for palindromes),
            // change a character to ensure it's different
            if (reversedSignature.toString().equals(originalSignature) && !originalSignature.isEmpty()) {
                char firstChar = reversedSignature.charAt(0);
                reversedSignature.setCharAt(0, generateDifferentChar(firstChar, CHAR_GENERATOR_A_B));
            }

            // Return the original validation with the different signature
            return parts[0] + "." + parts[1] + "." + reversedSignature;
        } catch (IllegalArgumentException | IllegalStateException e) {
            return token; // In case of any error, return the original validation
        }
    }

    /**
     * Changes the key ID (kid) in the header to an invalid value.
     *
     * @param token the original JWT Token
     * @return the tampered validation
     */
    private static String changeKeyIdToInvalid(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return token; // Not a valid JWT Token
        }

        try {
            // Decode the header
            String decodedHeader = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            // Replace the kid with an invalid value
            String modifiedHeader = decodedHeader.replaceAll("\"kid\"\\s*:\\s*\"[^\"]*\"", "\"kid\":\"invalid-key-id\"");
            // Encode the modified header
            String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(modifiedHeader.getBytes(StandardCharsets.UTF_8));

            // Return the modified validation
            return encodedHeader + "." + parts[1] + "." + parts[2];
        } catch (IllegalArgumentException | IllegalStateException e) {
            return token; // In case of any error, return the original validation
        }
    }

    /**
     * Removes the key ID (kid) from the header.
     *
     * @param token the original JWT Token
     * @return the tampered validation
     */
    @SuppressWarnings("java:S5852") // owolff: Safe enough for unit-tests
    private static String removeKeyId(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return token; // Not a valid JWT Token
        }

        try {
            // Decode the header
            String decodedHeader = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            // Remove the kid claim
            String modifiedHeader = decodedHeader.replaceAll(",?\\s*\"kid\"\\s*:\\s*\"[^\"]*\"", "");
            // Encode the modified header
            String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(modifiedHeader.getBytes(StandardCharsets.UTF_8));

            // Return the modified validation
            return encodedHeader + "." + parts[1] + "." + parts[2];
        } catch (IllegalArgumentException | IllegalStateException e) {
            return token; // In case of any error, return the original validation
        }
    }
}
