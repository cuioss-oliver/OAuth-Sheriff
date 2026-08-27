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
package de.cuioss.sheriff.token.validation.jwks;

import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.transport.JwksType;
import de.cuioss.sheriff.token.commons.transport.LoaderStatus;
import de.cuioss.sheriff.token.commons.transport.LoadingStatusProvider;
import de.cuioss.sheriff.token.validation.jwks.key.KeyInfo;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * Interface for loading JSON Web Keys (JWK) from various sources with async initialization.
 * <p>
 * Implementations load keys from HTTP endpoints, files, or memory. The interface follows
 * an async initialization pattern where {@link #initJWKSLoader(SecurityEventCounter)} triggers
 * loading and returns a CompletableFuture, while {@link #getKeyInfo(String)} performs retrieval only.
 * <p>
 * Usage pattern:
 * <pre>
 * JwksLoader loader = new HttpJwksLoader(config);
 * CompletableFuture&lt;LoaderStatus&gt; initFuture = loader.initJWKSLoader(securityEventCounter);
 *
 * // Later, after initialization completes
 * Optional&lt;KeyInfo&gt; keyInfo = loader.getKeyInfo("key-id");
 * </pre>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@SuppressWarnings("JavadocLinkAsPlainText")
public interface JwksLoader extends LoadingStatusProvider {

    /**
     * Retrieves a key by its ID from loaded keys.
     * <p>
     * This method performs retrieval only - no loading or initialization.
     * Keys must be loaded via {@link #initJWKSLoader(SecurityEventCounter)} first.
     *
     * @param kid the key ID
     * @return an Optional containing the key info if found, empty otherwise
     */
    Optional<KeyInfo> getKeyInfo(String kid);

    /**
     * Gets the type of JWKS source used by this loader.
     *
     * @return the JWKS source type
     */
    JwksType getJwksType();

    /**
     * Gets the issuer identifier associated with this JWKS loader.
     * <p>
     * For HTTP-based loaders using well-known discovery, this returns the issuer
     * identifier from the discovery document. For other loaders, this may return
     * an empty Optional if no issuer identifier is configured or available.
     * </p>
     *
     * @return an Optional containing the issuer identifier if available, empty otherwise
     */
    Optional<String> getIssuerIdentifier();


    /**
     * Initializes the JwksLoader with the provided SecurityEventCounter and triggers
     * asynchronous loading of key material.
     * <p>
     * This method should be called after construction to complete the initialization
     * of the JWKS loader with the security event counter for tracking security events
     * and to begin loading the JWKS content asynchronously.
     * </p>
     * <p>
     * The returned CompletableFuture will complete when the initial loading of keys
     * is finished, with a LoaderStatus indicating the result of the loading operation.
     * </p>
     *
     * @param securityEventCounter the counter for security events, must not be null
     * @return a CompletableFuture that completes when keys are loaded, with the final LoaderStatus
     * @throws NullPointerException if securityEventCounter is null
     */
    CompletableFuture<LoaderStatus> initJWKSLoader(SecurityEventCounter securityEventCounter);
}
