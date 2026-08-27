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
package de.cuioss.sheriff.token.validation.domain.claim;

import de.cuioss.tools.logging.CuiLogger;

import java.util.*;

/**
 * Utility class for handling collection-based claims in JWT tokens.
 * <p>
 * This class encapsulates the logic for working with claims that contain collections
 * of values (like scopes, roles, or groups). It provides methods to:
 * <ul>
 *   <li>Retrieve the collection values</li>
 *   <li>Check if all expected values are present</li>
 *   <li>Determine which expected values are missing</li>
 *   <li>Log debug information about missing values</li>
 * </ul>
 * <p>
 * The class is designed to work with any {@link ClaimValue} that contains a collection,
 * making it reusable across different claim types like scopes, roles, and groups.
 * <p>
 * Usage example:
 * <pre>
 * // Create a handler for a scope claim
 * Optional&lt;ClaimValue&gt; scopeClaim = token.getClaimOption(ClaimName.SCOPE);
 * if (scopeClaim.isPresent()) {
 *     CollectionClaimHandler handler = new CollectionClaimHandler(scopeClaim.get());
 *
 *     // Check if all required scopes are present
 *     boolean hasAllScopes = handler.providesValues(requiredScopes);
 *
 *     // Get missing scopes
 *     Set&lt;String&gt; missingScopes = handler.determineMissingValues(requiredScopes);
 * }
 * </pre>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public class CollectionClaimHandler {

    private static final CuiLogger LOGGER = new CuiLogger(CollectionClaimHandler.class);

    private final ClaimValue claimValue;

    public CollectionClaimHandler(ClaimValue claimValue) {
        this.claimValue = claimValue;
    }

    /**
     * Gets the values from the claim.
     *
     * @return a List of string values from the claim
     * @throws IllegalStateException if the claim value is not of type STRING_LIST
     */
    private List<String> getValues() {
        if (claimValue.getType() != ClaimValueType.STRING_LIST) {
            throw new IllegalStateException("Claim value is not a collection type: " + claimValue.getType());
        }
        return claimValue.getAsList();
    }

    /**
     * Checks if the claim provides all expected values.
     * <p>
     * An empty collection is considered satisfied (returns true), since there are
     * no values to check against.
     *
     * @param expectedValues the values to check for, must not be null
     * @return true if the claim contains all expected values, false otherwise
     * @throws NullPointerException if expectedValues is null
     */
    public boolean providesValues(Collection<String> expectedValues) {
        Objects.requireNonNull(expectedValues, "expectedValues must not be null");
        if (expectedValues.isEmpty()) {
            LOGGER.debug("No values to check against");
            return true;
        }
        var availableValues = getValues();
        @SuppressWarnings("SlowListContainsAll")
        var result = availableValues.containsAll(expectedValues);
        LOGGER.debug("Value check result=%s (expected=%s, available=%s)", result, expectedValues, availableValues);
        return result;
    }

    /**
     * Checks if the claim provides all expected values and logs debug information if any are missing.
     *
     * @param expectedValues the values to check for
     * @param logContext additional context information for logging
     * @param givenLogger the logger to use for logging
     * @return true if the claim contains all expected values, false otherwise
     */
    public boolean providesValuesAndDebugIfValuesMissing(Collection<String> expectedValues, String logContext,
            CuiLogger givenLogger) {
        Set<String> delta = determineMissingValues(expectedValues);
        if (delta.isEmpty()) {
            givenLogger.trace("All expected values are present: %s, %s", expectedValues, logContext);
            return true;
        }
        givenLogger.debug(
                "Current claim does not provide all needed values:\nMissing in claim='%s',\nExpected='%s'\nPresent in claim='%s', %s",
                delta, expectedValues, getValues(), logContext);
        return false;
    }

    /**
     * Determines which expected values are missing from the claim.
     *
     * @param expectedValues the values to check for
     * @return an empty Set if the claim provides all expected values, otherwise a
     *         {@link TreeSet} containing all missing values
     */
    public Set<String> determineMissingValues(Collection<String> expectedValues) {
        if (providesValues(expectedValues)) {
            return Set.of();
        }
        Set<String> valueDelta = new TreeSet<>(expectedValues);
        getValues().forEach(valueDelta::remove);
        return valueDelta;
    }
}
