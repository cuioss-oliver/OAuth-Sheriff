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
 * RP-initiated logout — the OpenID Connect {@code end_session_endpoint} flow ({@code CLIENT-13}).
 * <p>
 * {@link de.cuioss.sheriff.token.client.logout.EndSessionFlow} builds the front-channel logout
 * redirect, refusing to build without an {@code id_token_hint} or {@code state} and validating the
 * {@code post_logout_redirect_uri} through
 * {@link de.cuioss.sheriff.token.client.logout.PostLogoutRedirectValidator}, which matches only by
 * exact, whole-string equality against a registered allow-list (open-redirect defence). Revoking the
 * session's held tokens is done via the {@code lifecycle} package before redirecting.
 *
 * @since 1.0
 */
@NullMarked
package de.cuioss.sheriff.token.client.logout;

import org.jspecify.annotations.NullMarked;
