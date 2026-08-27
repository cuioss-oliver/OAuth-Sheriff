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

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.List;

/**
 * Represents a typed claim value in a JWT Token.
 * <p>
 * This class provides a type-safe representation of JWT claim values,
 * supporting multiple claim value types including:
 * <ul>
 *   <li>String values - for simple claims like 'sub', 'iss'</li>
 *   <li>Date/time values - for temporal claims like 'exp', 'iat', 'nbf'</li>
 *   <li>String lists - for array claims like 'aud', 'scopes'</li>
 * </ul>
 * <p>
 * The implementation maintains the original string representation from the token
 * to preserve full fidelity with the source data, while also providing convenient
 * typed access to the parsed value.
 * <p>
 * All static factory methods create immutable instances, making this class
 * thread-safe and suitable for concurrent use. The class provides comprehensive
 * equality checking and properly implements {@code Serializable} to support
 * caching or serialization scenarios.
 * <p>
 * For more details on JWT claim handling, see the
 * <a href="https://github.com/cuioss/TokenSheriff/tree/main/doc/validation/architecture.adoc#token-structure">Token Structure</a>
 * specification.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see ClaimName
 * @see ClaimValueType
 */
@ToString
@EqualsAndHashCode
public class ClaimValue implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * The original string representation of this claim value as it appeared in the token.
     * All claim values must preserve their original string representation to maintain
     * fidelity with the original validation format.
     */
    @Getter
    private final String originalString;

    /**
     * The type of this claim value.
     */
    @Getter
    private final ClaimValueType type;

    /**
     * Only relevant for {@link ClaimValueType#STRING_LIST}
     */
    @Getter
    // Must not be null, but may be empty
    private final List<String> asList;

    /**
     * Only relevant for {@link ClaimValueType#DATETIME}
     */
    @Getter
    private final OffsetDateTime dateTime;

    /**
     * Constructor for ClaimValue.
     *
     * @param originalString the original string representation of the claim value
     * @param type the type of the claim value
     * @param asList the list of string values (only relevant for STRING_LIST)
     * @param dateTime the OffsetDateTime value (only relevant for DATETIME)
     */
    private ClaimValue(String originalString, ClaimValueType type,
            List<String> asList, OffsetDateTime dateTime) {
        this.originalString = originalString;
        this.type = type;
        this.asList = asList;
        this.dateTime = dateTime;
    }

    /**
     * Checks if the claim value is NOT present for the current {@link ClaimValueType}.
     * For STRING_LIST, it checks if the list is empty.
     * For DATETIME, it checks if the dateTime is null.
     *
     * @return true if the claim value is NOT present for the claim value type, false otherwise
     */
    public boolean isNotPresentForClaimValueType() {
        return switch (getType()) {
            case STRING_LIST -> asList.isEmpty();
            case DATETIME -> dateTime == null;
            default -> false;
        };
    }

    /**
     * Creates a ClaimValue for a plain string. With {@link ClaimValueType#STRING}
     *
     * @param originalString the original string representation of the claim value
     */
    public static ClaimValue forPlainString(String originalString) {
        return new ClaimValue(originalString, ClaimValueType.STRING, List.of(), null);
    }

    /**
     * Creates a ClaimValue for a list of strings. With {@link ClaimValueType#STRING_LIST}.
     *
     * @param originalString the original string representation of the claim value
     * @param list           the list of string values
     */
    public static ClaimValue forList(String originalString, List<String> list) {
        return new ClaimValue(originalString, ClaimValueType.STRING_LIST, list, null);
    }

    /**
     * Creates a ClaimValue for a datetime. With {@link ClaimValueType#DATETIME}
     *
     * @param originalString the original string representation of the claim value
     * @param dateTime       the OffsetDateTime value
     */
    public static ClaimValue forDateTime(String originalString, OffsetDateTime dateTime) {
        return new ClaimValue(originalString, ClaimValueType.DATETIME, List.of(), dateTime);
    }

}
