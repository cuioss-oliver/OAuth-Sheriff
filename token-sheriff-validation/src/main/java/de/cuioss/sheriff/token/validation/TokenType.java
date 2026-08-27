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
package de.cuioss.sheriff.token.validation;

import de.cuioss.sheriff.token.validation.domain.claim.ClaimName;
import lombok.Getter;

import java.util.Collections;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

import static de.cuioss.sheriff.token.validation.domain.claim.ClaimName.*;

/**
 * Defines the supported token types within the authentication system.
 * Each type represents a specific OAuth2/OpenID Connect token category with its mandatory claims.
 * <p>
 * The supported token types are:
 * <ul>
 *   <li>{@link #ACCESS_TOKEN}: Standard OAuth2 access token</li>
 *   <li>{@link #ID_TOKEN}: OpenID Connect ID-Token</li>
 *   <li>{@link #REFRESH_TOKEN}: OAuth2 Refresh-Token</li>
 * </ul>
 * <p>
 * Implements requirements:
 * <ul>
 *   <li><a href="../../../../../../../../../doc/validation/requirements.adoc#VALIDATION-1.2">VALIDATION-1.2: Token Types</a></li>
 * </ul>
 * <p>
 * For more detailed specifications, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#_token_architecture_and_types">Technical Components Specification - Token Architecture and Types</a>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public enum TokenType {

    ACCESS_TOKEN(new TreeSet<>(List.of(ISSUER, EXPIRATION, ISSUED_AT, SUBJECT))),
    ID_TOKEN(new TreeSet<>(List.of(ISSUER, EXPIRATION, ISSUED_AT, SUBJECT, AUDIENCE))),
    REFRESH_TOKEN(Collections.emptySortedSet());

    @Getter
    private final SortedSet<ClaimName> mandatoryClaims;

    /**
     * Constructor for TokenType.
     *
     * @param mandatoryClaims the mandatory claims, stored as an unmodifiable view
     */
    TokenType(SortedSet<ClaimName> mandatoryClaims) {
        this.mandatoryClaims = Collections.unmodifiableSortedSet(mandatoryClaims);
    }
}
