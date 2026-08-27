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
 * Runtime module of the Quarkus extension for the Token-Sheriff OIDC/OAuth client engine.
 * <p>
 * This extension binds the framework-agnostic {@code token-sheriff-client} engine into Quarkus. It is
 * a <em>separate</em> extension that depends on the existing {@code token-sheriff-validation-quarkus}
 * extension (reusing its validation CDI wiring) rather than folding the client into it — this keeps
 * opt-in clean: an application adds the client extension only when it needs the outbound flows.
 * The build-time counterpart lives in {@code token-sheriff-client-quarkus-deployment}.
 * <p>
 * <strong>Status:</strong> wired, empty skeleton (Plan 05). The extension registers the
 * {@code token-sheriff-client} feature and assembles against the reactor; runtime producers and
 * configuration land with the client flows (Plan 06).
 *
 * @author Oliver Wolff
 */
package de.cuioss.sheriff.token.client.quarkus;
