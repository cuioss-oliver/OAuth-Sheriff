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

import de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig;
import de.cuioss.sheriff.token.commons.transport.JwksType;
import de.cuioss.sheriff.token.validation.jwks.http.HttpJwksLoader;
import de.cuioss.sheriff.token.validation.jwks.key.JWKSKeyLoader;
import de.cuioss.tools.logging.CuiLogger;
import lombok.experimental.UtilityClass;

/**
 * Factory for creating instances of {@link JwksLoader}.
 * <p>
 * Key features:
 * <ul>
 *   <li>Creates appropriate loader based on the JWKS URL</li>
 *   <li>Supports HTTP and file-based JWKS sources</li>
 *   <li>Integrates with SecurityEventCounter for security event tracking</li>
 * </ul>
 * <p>
 * Usage example:
 * <pre>
 * SecurityEventCounter securityEventCounter = new SecurityEventCounter();
 * HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
 *     .jwksUrl("https://auth.example.com/.well-known/jwks.json")
 *     .refreshIntervalSeconds(60)
 *     .build();
 *
 * JwksLoader loader = JwksLoaderFactory.createHttpLoader(config, securityEventCounter);
 * CompletableFuture&lt;LoaderStatus&gt; initFuture = loader.initJWKSLoader(securityEventCounter);
 *
 * // After initialization completes
 * Optional&lt;KeyInfo&gt; keyInfo = loader.getKeyInfo("kid123");
 * </pre>
 * <p>
 * See specification: <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#jwks-integration">Technical Components Specification - JwksLoader</a>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@UtilityClass
public class JwksLoaderFactory {

    private static final CuiLogger LOGGER = new CuiLogger(JwksLoaderFactory.class);


    /**
     * Creates a JwksLoader that loads JWKS from an HTTP endpoint.
     * The SecurityEventCounter must be initialized separately via initJWKSLoader().
     *
     * @param config the configuration for the HTTP JWKS loader
     * @return an instance of JwksLoader
     */
   
    public static JwksLoader createHttpLoader(HttpJwksLoaderConfig config) {
        return new HttpJwksLoader(config);
    }


    /**
     * Creates a JwksLoader that loads JWKS from a file.
     * The SecurityEventCounter must be initialized separately via initJWKSLoader().
     *
     * @param filePath the path to the JWKS file
     * @return an instance of JwksLoader
     */
   
    public static JwksLoader createFileLoader(String filePath) {
        LOGGER.debug("Resolving key loader for JWKS file: %s", filePath);
        return JWKSKeyLoader.builder()
                .jwksFilePath(filePath) // Store the file path for deferred loading
                .jwksType(JwksType.FILE)
                .build();
    }

    /**
     * Creates a JwksLoader that loads JWKS from in-memory string content.
     * The SecurityEventCounter must be initialized separately via initJWKSLoader().
     *
     * @param jwksContent the JWKS content as a string
     * @return an instance of JwksLoader
     */
   
    public static JwksLoader createInMemoryLoader(String jwksContent) {
        LOGGER.debug("Resolving key loader for in-memory JWKS data");
        return JWKSKeyLoader.builder()
                .jwksContent(jwksContent) // Store the content for deferred loading
                .jwksType(JwksType.MEMORY)
                .build();
    }

}
