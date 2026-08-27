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
 * RFC 9457 rendering of the Token-Sheriff typed exception hierarchy at the Quarkus HTTP edge.
 * <p>
 * Holds {@link de.cuioss.sheriff.token.quarkus.error.ProblemDetailExceptionMapper}, which maps
 * {@link de.cuioss.sheriff.token.commons.error.TokenSheriffException} subtypes to
 * {@code application/problem+json}. See {@code doc/commons/specification/error-model.adoc}.
 *
 * @author Oliver Wolff
 */
package de.cuioss.sheriff.token.quarkus.error;
