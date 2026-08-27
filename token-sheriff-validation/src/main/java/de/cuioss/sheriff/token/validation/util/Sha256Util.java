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
package de.cuioss.sheriff.token.validation.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Small utility wrapping {@link MessageDigest} SHA-256 digest computation.
 * <p>
 * SHA-256 is required to be present by the Java Security Standard Algorithm Names
 * specification, so the checked {@link NoSuchAlgorithmException} is translated to an
 * {@link IllegalStateException} (it can only occur on a broken JRE).
 *
 * @since 1.0
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class Sha256Util {

    /**
     * Computes the SHA-256 digest of the given input.
     *
     * @param input the bytes to digest, must not be {@code null}
     * @return the 32-byte SHA-256 digest
     * @throws IllegalStateException if the SHA-256 algorithm is not available (broken JRE)
     */
    public static byte[] digest(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is required by the Java specification; this should never happen
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
