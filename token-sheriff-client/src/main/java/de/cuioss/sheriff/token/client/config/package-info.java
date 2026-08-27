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
 * Immutable, thread-safe configuration for the Token-Sheriff OIDC/OAuth client engine.
 * <p>
 * {@link de.cuioss.sheriff.token.client.config.ClientConfiguration} describes how the client
 * talks to one authorization server (issuer, {@code client_id}, secret, scopes, exact
 * {@code redirect_uri}) and which
 * {@link de.cuioss.sheriff.token.client.config.ClientAuthMethod client-authentication method}
 * it presents. Both types are value objects shared read-only across concurrent flows for that
 * issuer ({@code CLIENT-22}).
 *
 * @since 1.0
 */
@NullMarked
package de.cuioss.sheriff.token.client.config;

import org.jspecify.annotations.NullMarked;
