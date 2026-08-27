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
 * Client authentication strategies for the authenticated back-channel endpoints.
 * <p>
 * {@link de.cuioss.sheriff.token.client.auth.ClientAuthentication} decorates a token / PAR /
 * revocation / introspection request with the configured method:
 * {@link de.cuioss.sheriff.token.client.auth.ClientSecretBasicAuth} and
 * {@link de.cuioss.sheriff.token.client.auth.ClientSecretPostAuth} (shared secret over TLS),
 * {@link de.cuioss.sheriff.token.client.auth.PrivateKeyJwtAuth} (RFC 7523 signed assertion), and
 * {@link de.cuioss.sheriff.token.client.auth.MtlsClientAuth} (RFC 8705 certificate binding).
 * {@link de.cuioss.sheriff.token.client.auth.ClientAuthenticationSelector} picks the strongest
 * method the authorization server advertises, refusing to downgrade ({@code CLIENT-4}).
 *
 * @since 1.0
 */
@NullMarked
package de.cuioss.sheriff.token.client.auth;

import org.jspecify.annotations.NullMarked;
