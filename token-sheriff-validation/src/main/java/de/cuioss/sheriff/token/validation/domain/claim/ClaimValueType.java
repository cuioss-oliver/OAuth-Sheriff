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


/**
 * Defines the types of claim values supported by the system.
 * Based on the OAuth 2.0/OpenID Connect specifications and actual usage patterns.
 *
 * @since 1.0
 */
public enum ClaimValueType {
    /**
     * Represents a string value claim like "iss", "sub", etc.
     */
    STRING,

    /**
     * Represents a claim containing a list of strings.
     * Used for arrays in JSON and for claims that logically represent collections
     * like "roles", "groups", and "scopes".
     */
    STRING_LIST,

    /**
     * Represents a datetime value, typically stored as numeric timestamp
     * but exposed as OffsetDateTime in the API.
     */
    DATETIME
}
