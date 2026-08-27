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
 * Metric-identifier surface of the {@code commons} base layer.
 * <p>
 * Holds {@link de.cuioss.sheriff.token.commons.metrics.MetricIdentifier} — the
 * {@code sheriff.token.*} metric names defined once here so the validation and (later) client
 * capabilities share one contract. Each Quarkus extension wires these identifiers to
 * Micrometer; the identifiers themselves carry no Micrometer dependency.
 * <p>
 * As part of the {@code commons} base layer, this package must not depend on the
 * {@code de.cuioss.sheriff.token.validation} packages (the ArchUnit boundary — see
 * {@code doc/commons/architecture.adoc}).
 *
 * @author Oliver Wolff
 * @see de.cuioss.sheriff.token.commons.metrics.MetricIdentifier
 */
package de.cuioss.sheriff.token.commons.metrics;
