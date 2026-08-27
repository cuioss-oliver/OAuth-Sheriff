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
 * Security-event surface of the {@code commons} base layer.
 * <p>
 * Holds {@link de.cuioss.sheriff.token.commons.events.SecurityEventCounter} and its
 * {@link de.cuioss.sheriff.token.commons.events.EventCategory}, shared by the validation
 * packages and (later) the OIDC client so both count events against one surface.
 * <p>
 * As part of the {@code commons} base layer, this package must not depend on the
 * {@code de.cuioss.sheriff.token.validation} packages; the boundary is enforced by ArchUnit
 * (see {@code doc/commons/architecture.adoc}).
 *
 * @author Oliver Wolff
 * @see de.cuioss.sheriff.token.commons.events.SecurityEventCounter
 */
package de.cuioss.sheriff.token.commons.events;
