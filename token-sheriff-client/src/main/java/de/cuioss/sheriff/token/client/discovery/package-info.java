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
 * OpenID Connect / OAuth 2.0 authorization-server discovery for the client engine.
 * <p>
 * {@link de.cuioss.sheriff.token.client.discovery.DiscoveryResolver} fetches the AS
 * {@code .well-known/openid-configuration} document over the commons-blessed cui-http
 * {@code HttpHandler} (TLS enforced) and maps it into an immutable
 * {@link de.cuioss.sheriff.token.client.discovery.ProviderMetadata} — the resolved endpoint URLs
 * plus the capability flags (PKCE {@code S256}, PAR, DPoP, end-session) the flows branch on. The
 * package adds no transport hardening of its own; it inherits the handler's TLS/SSRF posture.
 *
 * @since 1.0
 */
@NullMarked
package de.cuioss.sheriff.token.client.discovery;

import org.jspecify.annotations.NullMarked;
