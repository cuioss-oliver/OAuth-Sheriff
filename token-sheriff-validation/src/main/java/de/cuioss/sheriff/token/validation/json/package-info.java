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
/**
 * JSON mapping types for JWT validation using DSL-JSON.
 * <p>
 * This package contains pure mapper types for JSON deserialization using DSL-JSON's
 * compile-time code generation. All types follow a "nullable by default" pattern
 * for permissive JSON parsing - validation happens later in the validation chain.
 * <p>
 * Key characteristics:
 * <ul>
 *   <li>All record parameters are nullable (unspecified nullness)</li>
 *   <li>Optional accessor methods provide null-safe access</li>
 *   <li>No validation logic in mapper types</li>
 *   <li>DSL-JSON @CompiledJson annotations for performance</li>
 * </ul>
 * <p>
 * The @NullUnmarked annotation removes JSpecify nullability enforcement,
 * allowing natural nullable-by-default behavior for JSON mapping scenarios.
 *
 */
@NullUnmarked
package de.cuioss.sheriff.token.validation.json;

import org.jspecify.annotations.NullUnmarked;