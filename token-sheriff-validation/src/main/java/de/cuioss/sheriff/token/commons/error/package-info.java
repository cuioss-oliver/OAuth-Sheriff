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
 * Error-model surface of the {@code commons} base layer.
 * <p>
 * Defines the typed exception hierarchy that library code throws
 * ({@link de.cuioss.sheriff.token.commons.error.TokenSheriffException} and its subtypes).
 * Library code raises these; the HTTP edges map them to {@code application/problem+json} per
 * <a href="https://www.rfc-editor.org/rfc/rfc9457">RFC 9457</a>. Commons never produces the
 * problem document itself.
 * <p>
 * As part of the {@code commons} base layer, this package must not depend on the
 * {@code de.cuioss.sheriff.token.validation} packages (the ArchUnit boundary — see
 * {@code doc/commons/architecture.adoc}).
 *
 * @author Oliver Wolff
 * @see de.cuioss.sheriff.token.commons.error.TokenSheriffException
 */
package de.cuioss.sheriff.token.commons.error;
