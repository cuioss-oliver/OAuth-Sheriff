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
 * Server-side token lifecycle — storage, proactive refresh, and revocation
 * ({@code CLIENT-17} / {@code CLIENT-18} / {@code CLIENT-19}).
 * <p>
 * {@link de.cuioss.sheriff.token.client.lifecycle.TokenStore} is the pluggable storage SPI (default
 * {@link de.cuioss.sheriff.token.client.lifecycle.InMemoryTokenStore}) keeping retrieved tokens off
 * the browser; {@link de.cuioss.sheriff.token.client.lifecycle.StoredToken} is the stored bundle that
 * carries the sender-constraint {@link de.cuioss.sheriff.token.client.dpop.ConstraintBinding} so it
 * survives storage and refresh. {@link de.cuioss.sheriff.token.client.lifecycle.RefreshScheduler}
 * decides when to refresh proactively;
 * {@link de.cuioss.sheriff.token.client.lifecycle.TokenLifecycleManager} orchestrates store / refresh
 * / revoke-and-clear with a fail-closed, no-stale-read logout;
 * {@link de.cuioss.sheriff.token.client.lifecycle.RevocationClient} revokes tokens at the AS
 * (RFC 7009).
 *
 * @since 1.0
 */
@NullMarked
package de.cuioss.sheriff.token.client.lifecycle;

import org.jspecify.annotations.NullMarked;
