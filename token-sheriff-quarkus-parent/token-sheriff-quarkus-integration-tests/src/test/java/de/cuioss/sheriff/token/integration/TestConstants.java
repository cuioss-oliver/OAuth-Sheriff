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
package de.cuioss.sheriff.token.integration;

/**
 * Shared test constants used across multiple integration test classes.
 */
public final class TestConstants {

    /** HTTP Authorization header name. */
    public static final String AUTHORIZATION = "Authorization";

    /** Bearer token prefix including trailing space. */
    public static final String BEARER_PREFIX = "Bearer ";

    /** JSON content type. */
    public static final String CONTENT_TYPE_JSON = "application/json";

    /** Path for access-token validation endpoint. */
    public static final String JWT_VALIDATE_PATH = "/jwt/validate";

    /** JSON field name for the token in request bodies. */
    public static final String TOKEN_FIELD_NAME = "token";

    /** JSON field name for the validation result flag. */
    public static final String VALID = "valid";

    /** JSON field name for the validation result message. */
    public static final String MESSAGE = "message";

    private TestConstants() {
        // utility class
    }
}
