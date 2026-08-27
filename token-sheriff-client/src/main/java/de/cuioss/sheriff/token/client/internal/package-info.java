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
 * Client-engine-internal transport and encoding utilities.
 * <p>
 * These types are implementation details of the client engine, not part of its public API:
 * {@link de.cuioss.sheriff.token.client.internal.BackChannelHttp} centralises the shared back-channel
 * egress/SSRF and TLS controls; {@link de.cuioss.sheriff.token.client.internal.BoundedContentBodyHandler}
 * enforces the response payload ceiling during the read;
 * {@link de.cuioss.sheriff.token.client.internal.FormEncoder} and
 * {@link de.cuioss.sheriff.token.client.internal.JsonEscaper} handle request/response encoding; and
 * {@link de.cuioss.sheriff.token.client.internal.LogSanitizer} neutralizes externally-sourced values
 * before they are logged (CWE-117). {@link de.cuioss.sheriff.token.client.internal.ClientLogMessages}
 * holds the package's structured {@code LogRecord} definitions.
 *
 * @since 1.0
 */
@NullMarked
package de.cuioss.sheriff.token.client.internal;

import org.jspecify.annotations.NullMarked;
