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
package de.cuioss.sheriff.token.commons.transport;

/**
 * Common interface for components that provide health status information.
 * <p>
 * This interface unifies health checking across different OAuth/JWT validation components
 * by providing a consistent way to check component health and retrieve detailed status information.
 * <p>
 * Implementation requirements:
 * <ul>
 *   <li>Implementations must be thread-safe for concurrent access</li>
 *   <li>{@link #getLoaderStatus()} must be non-blocking and return immediately</li>
 *   <li>Status checks must NOT trigger I/O operations or network requests</li>
 * </ul>
 * <p>
 * Usage example with OAuth/JWT components:
 * <pre>
 * LoadingStatusProvider jwksLoader = ...;
 * LoaderStatus status = jwksLoader.getLoaderStatus();
 * if (status == LoaderStatus.OK) {
 *     // JWKS loader is healthy and ready to validate tokens
 * } else if (status == LoaderStatus.ERROR) {
 *     // Handle error state in JWT validation
 * } else {
 *     // Handle undefined or loading state
 * }
 * </pre>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public interface LoadingStatusProvider {

    /**
     * Gets the current status of the loading operation without blocking.
     * <p>
     * This method must be non-blocking and return immediately with the current cached status.
     * It must NOT trigger any I/O operations, network requests, or other potentially blocking operations.
     * <p>
     * The returned status values:
     * <ul>
     *   <li>{@link LoaderStatus#OK} - Component is operational and healthy</li>
     *   <li>{@link LoaderStatus#ERROR} - Component encountered an error</li>
     *   <li>{@link LoaderStatus#LOADING} - Component is in the process of loading or initializing</li>
     *   <li>{@link LoaderStatus#UNDEFINED} - Initial state, not yet initialized</li>
     * </ul>
     * <p>
     * Implementation requirements:
     * <ul>
     *   <li>Must be thread-safe for concurrent calls</li>
     *   <li>Must return immediately without blocking</li>
     *   <li>Must NOT perform any I/O operations or network requests</li>
     *   <li>Should return the current cached status from memory</li>
     *   <li>Required for MicroProfile Health compliance for readiness checks</li>
     *   <li>In exceptional cases, may return UNDEFINED rather than throwing</li>
     * </ul>
     *
     * @return the current status of the loading operation from cache/memory, never {@code null}
     */
    LoaderStatus getLoaderStatus();

    /**
     * Convenience method to check if the loader status is OK.
     * <p>
     * This method provides a simplified way to check if the component is healthy
     * without directly comparing the status enum.
     *
     * @return {@code true} if the component status is {@link LoaderStatus#OK}, {@code false} otherwise
     */
    default boolean isLoaderStatusOK() {
        return getLoaderStatus() == LoaderStatus.OK;
    }
}
