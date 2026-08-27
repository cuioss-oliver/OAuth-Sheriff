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
 * Sender-constraining for retrieved access tokens — DPoP (RFC 9449) and mTLS-bound (RFC 8705),
 * {@code CLIENT-11}.
 * <p>
 * {@link de.cuioss.sheriff.token.client.dpop.DpopProofGenerator} builds the per-request DPoP proof
 * JWT and exposes the proof-key thumbprint ({@code cnf.jkt});
 * {@link de.cuioss.sheriff.token.client.dpop.SenderConstraint} applies the DPoP proof header (or,
 * for mTLS, relies on the transport-level certificate binding) to the token request and records the
 * resulting {@link de.cuioss.sheriff.token.client.dpop.ConstraintBinding}. The binding is carried
 * alongside the stored token by the token lifecycle so the constraint survives storage and
 * refresh ({@code CLIENT-18}). Verifying that a presented token matches its confirmed key is
 * inherited from the validation pipeline ({@code VALIDATION-8.7}) and is not re-implemented here.
 *
 * @since 1.0
 */
@NullMarked
package de.cuioss.sheriff.token.client.dpop;

import org.jspecify.annotations.NullMarked;
