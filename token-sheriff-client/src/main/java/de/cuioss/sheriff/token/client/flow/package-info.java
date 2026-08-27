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
 * OAuth 2.0 / OpenID Connect grant flows for the client engine.
 * <p>
 * {@link de.cuioss.sheriff.token.client.flow.TokenEndpointClient} is the thin cui-http
 * {@code HttpHandler} wrapper for the authenticated back-channel token-endpoint {@code POST}
 * (design fork 1). {@link de.cuioss.sheriff.token.client.flow.ClientCredentialsFlow} drives the
 * {@code client_credentials} grant on top of it, validating every retrieved token through the
 * validation pipeline. {@link de.cuioss.sheriff.token.client.flow.RefreshFlow} drives the
 * {@code refresh_token} grant and {@link de.cuioss.sheriff.token.client.flow.AuthorizationCodeFlow}
 * drives the {@code authorization_code} + PKCE flow on the same back-channel client.
 *
 * @since 1.0
 */
@NullMarked
package de.cuioss.sheriff.token.client.flow;

import org.jspecify.annotations.NullMarked;
