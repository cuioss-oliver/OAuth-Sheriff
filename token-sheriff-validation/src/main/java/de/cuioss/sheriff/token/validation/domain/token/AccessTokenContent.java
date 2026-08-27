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
package de.cuioss.sheriff.token.validation.domain.token;

import de.cuioss.sheriff.token.validation.TokenType;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import de.cuioss.sheriff.token.validation.domain.claim.ClaimValue;
import de.cuioss.sheriff.token.validation.domain.claim.CollectionClaimHandler;
import de.cuioss.tools.logging.CuiLogger;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.io.Serial;
import java.util.*;

/**
 * Represents the content of an OAuth 2.0 access token.
 * <p>
 * This class provides access to access token specific claims and functionality, including:
 * <ul>
 *   <li>Scope validation with detailed logging capabilities</li>
 *   <li>Role and group validation for role-based and group-based access control</li>
 *   <li>Access to audience claims</li>
 *   <li>User identity information (email, preferred username)</li>
 * </ul>
 * <p>
 * Access tokens typically contain:
 * <ul>
 *   <li>Standard JWT claims (iss, sub, exp, iat)</li>
 *   <li>OAuth-specific claims like scope/scopes and audience</li>
 *   <li>Optional identity claims depending on the authorization server</li>
 * </ul>
 * <p>
 * This implementation follows the standards defined in:
 * <ul>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc6749">RFC 6749 - OAuth 2.0</a></li>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 - JWT</a></li>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc8693">RFC 8693 - Token Exchange</a></li>
 * </ul>
 * <p>
 * For more details on token structure and usage, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#token-types">Token Types</a>
 * specification.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public final class AccessTokenContent extends BaseTokenContent {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new AccessTokenContent with the given claims and raw token.
     *
     * @param claims   the token claims
     * @param rawToken the raw token string
     */
    public AccessTokenContent(Map<String, ClaimValue> claims, String rawToken) {
        super(claims, rawToken, TokenType.ACCESS_TOKEN);
    }

    /**
     * Gets the audience claim value.
     * <p>
     * 'aud' is optional for {@link TokenType#ACCESS_TOKEN}.
     * Returns an empty set if not present (audience is optional for access tokens).
     *
     * @return the audience as a set of strings, or an empty set if not present
     */
    public Set<String> getAudience() {
        return getClaimOption(ClaimName.AUDIENCE)
                .map(ClaimValue::getAsList)
                .<Set<String>>map(list -> new LinkedHashSet<>(list))
                .orElse(Set.of());
    }

    /**
     * Gets the scopes from the token claims.
     * <p>
     * The scope claim is optional per RFC 9068 Section 2.2. If the scope claim is not
     * present in the token, an empty list is returned.
     *
     * @return a List of scope strings, or an empty list if the scope claim is not present
     */

    public List<String> getScopes() {
        return getClaimOption(ClaimName.SCOPE)
                .map(ClaimValue::getAsList)
                .orElse(List.of());
    }

    /**
     * Gets the roles from the token claims.
     * <p>
     * The "roles" claim is a common but not standardized claim used for role-based access control.
     *
     * @return a List of role strings, or an empty list if the roles claim is not present
     */
   
    public List<String> getRoles() {
        return getClaimOption(ClaimName.ROLES)
                .map(ClaimValue::getAsList)
                .orElse(List.of());
    }

    /**
     * Gets the groups from the token claims.
     * <p>
     * The "groups" claim is a common but not standardized claim used for group-based access control.
     *
     * @return a Set of group strings, or an empty set if the groups claim is not present
     */
    public Set<String> getGroups() {
        return getClaimOption(ClaimName.GROUPS)
                .map(ClaimValue::getAsList)
                .<Set<String>>map(list -> new LinkedHashSet<>(list))
                .orElse(Set.of());
    }

    /**
     * Gets the email address associated with this token, derived from the
     * {@link ClaimName#EMAIL} claim in the claims map.
     *
     * @return an Optional containing the email if present, or empty otherwise
     */
    public Optional<String> getEmail() {
        return getClaimOption(ClaimName.EMAIL).map(ClaimValue::getOriginalString);
    }

    /**
     * Gets the preferred username from the token claims.
     *
     * @return an Optional containing the preferred username if present, or empty otherwise
     */
    public Optional<String> getPreferredUsername() {
        return getClaimOption(ClaimName.PREFERRED_USERNAME).map(ClaimValue::getOriginalString);
    }

    // Design Decision: The *AndDebugIf*Missing methods (providesScopesAndDebugIfScopesAreMissing,
    // providesRolesAndDebugIfRolesMissing, providesGroupsAndDebugIfGroupsMissing) are intentional
    // public API for library consumers performing authorization checks with debug logging.
    // They have zero internal callers but are part of the 1.0 public contract.

    /**
     * Checks if the token provides all expected scopes.
     *
     * @param expectedScopes the scopes to check for
     * @return true if the token contains all expected scopes, false otherwise
     */
    public boolean providesScopes(Collection<String> expectedScopes) {
        return providesClaimValues(ClaimName.SCOPE, expectedScopes);
    }

    /**
     * Checks if the token provides all expected scopes and logs debug information if any are missing.
     *
     * @param expectedScopes the scopes to check for
     * @param logContext      additional context information for logging
     * @param logger          the logger to use for logging
     * @return true if the token contains all expected scopes, false otherwise.
     *         In contrast to {@link #providesScopes(Collection)} it logs missing scopes at debug level.
     */
    public boolean providesScopesAndDebugIfScopesAreMissing(Collection<String> expectedScopes, String logContext,
            CuiLogger logger) {
        return providesClaimValuesWithDebug(ClaimName.SCOPE, expectedScopes, logContext, logger);
    }

    /**
     * Determines which expected scopes are missing from the token.
     *
     * @param expectedScopes the scopes to check for
     * @return an empty Set if all expected scopes are present, otherwise a
     *         {@link TreeSet} containing the missing scopes
     */
    public Set<String> determineMissingScopes(Collection<String> expectedScopes) {
        return determineMissingClaimValues(ClaimName.SCOPE, expectedScopes);
    }

    /**
     * Checks if the token provides all expected roles.
     *
     * @param expectedRoles the roles to check for
     * @return true if the token contains all expected roles, false otherwise
     */
    public boolean providesRoles(Collection<String> expectedRoles) {
        return providesClaimValues(ClaimName.ROLES, expectedRoles);
    }

    /**
     * Checks if the token provides all expected roles and logs debug information if any are missing.
     *
     * @param expectedRoles the roles to check for
     * @param logContext     additional context information for logging
     * @param logger         the logger to use for logging
     * @return true if the token contains all expected roles, false otherwise
     */
    public boolean providesRolesAndDebugIfRolesMissing(Collection<String> expectedRoles, String logContext,
            CuiLogger logger) {
        return providesClaimValuesWithDebug(ClaimName.ROLES, expectedRoles, logContext, logger);
    }

    /**
     * Determines which expected roles are missing from the token.
     *
     * @param expectedRoles the roles to check for
     * @return an empty Set if all expected roles are present, otherwise a
     *         {@link TreeSet} containing the missing roles
     */
    public Set<String> determineMissingRoles(Collection<String> expectedRoles) {
        return determineMissingClaimValues(ClaimName.ROLES, expectedRoles);
    }

    /**
     * Checks if the token provides all expected groups.
     *
     * @param expectedGroups the groups to check for
     * @return true if the token contains all expected groups, false otherwise
     */
    public boolean providesGroups(Collection<String> expectedGroups) {
        return providesClaimValues(ClaimName.GROUPS, expectedGroups);
    }

    /**
     * Checks if the token provides all expected groups and logs debug information if any are missing.
     *
     * @param expectedGroups the groups to check for
     * @param logContext      additional context information for logging
     * @param logger          the logger to use for logging
     * @return true if the token contains all expected groups, false otherwise
     */
    public boolean providesGroupsAndDebugIfGroupsMissing(Collection<String> expectedGroups, String logContext,
            CuiLogger logger) {
        return providesClaimValuesWithDebug(ClaimName.GROUPS, expectedGroups, logContext, logger);
    }

    /**
     * Determines which expected groups are missing from the token.
     *
     * @param expectedGroups the groups to check for
     * @return an empty Set if all expected groups are present, otherwise a
     *         {@link TreeSet} containing the missing groups
     */
    public Set<String> determineMissingGroups(Collection<String> expectedGroups) {
        return determineMissingClaimValues(ClaimName.GROUPS, expectedGroups);
    }

    private boolean providesClaimValues(ClaimName claimName, Collection<String> expectedValues) {
        return getClaimOption(claimName)
                .map(claimValue -> new CollectionClaimHandler(claimValue).providesValues(expectedValues))
                .orElse(false);
    }

    private boolean providesClaimValuesWithDebug(ClaimName claimName, Collection<String> expectedValues,
            String logContext, CuiLogger logger) {
        return getClaimOption(claimName)
                .map(claimValue -> new CollectionClaimHandler(claimValue)
                        .providesValuesAndDebugIfValuesMissing(expectedValues, logContext, logger))
                .orElse(false);
    }

    private Set<String> determineMissingClaimValues(ClaimName claimName, Collection<String> expectedValues) {
        return getClaimOption(claimName)
                .map(claimValue -> new CollectionClaimHandler(claimValue).determineMissingValues(expectedValues))
                .orElse(new TreeSet<>(expectedValues));
    }
}
