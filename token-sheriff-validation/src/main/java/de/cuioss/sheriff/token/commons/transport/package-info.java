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
 * Transport surface of the {@code commons} base layer — all outbound IdP HTTP.
 * <p>
 * This package owns the framework-agnostic transport foundation that both token
 * validation and the client engine sit on: OIDC discovery
 * ({@link de.cuioss.sheriff.token.commons.transport.HttpWellKnownResolver} /
 * {@link de.cuioss.sheriff.token.commons.transport.WellKnownConfig}) and JWKS retrieval
 * ({@link de.cuioss.sheriff.token.commons.transport.HttpJwksLoaderConfig} /
 * {@link de.cuioss.sheriff.token.commons.transport.JwksHttpContentConverter}), together with
 * the shared JSON payload types ({@link de.cuioss.sheriff.token.commons.transport.Jwks},
 * {@link de.cuioss.sheriff.token.commons.transport.WellKnownResult}), the JSON parser security
 * configuration ({@link de.cuioss.sheriff.token.commons.transport.ParserConfig}) and the async
 * loading-status contract
 * ({@link de.cuioss.sheriff.token.commons.transport.LoadingStatusProvider}).
 * <p>
 * The seam is sharp: transport <em>moves bytes and parses payloads</em> (TLS enforcement, SSRF
 * defence, timeouts, response-size limits, retry/backoff, the {@code cui-http} client and
 * JWKS/discovery caching). It <strong>never interprets a token's trust</strong> — turning a
 * fetched {@link de.cuioss.sheriff.token.commons.transport.Jwks} document into verification key
 * material is the crypto concern owned by {@code de.cuioss.sheriff.token.validation.jwks}.
 * <p>
 * As part of the {@code commons} base layer, this package must not depend on the
 * {@code de.cuioss.sheriff.token.validation} packages (the ArchUnit boundary — see
 * {@code doc/commons/architecture.adoc}).
 *
 * @author Oliver Wolff
 * @see de.cuioss.sheriff.token.commons.transport.TransportLogMessages
 */
package de.cuioss.sheriff.token.commons.transport;
