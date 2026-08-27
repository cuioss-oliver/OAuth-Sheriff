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
 * MicroProfile Config surface for the Token-Sheriff OIDC/OAuth client Quarkus extension.
 * <p>
 * {@link de.cuioss.sheriff.token.client.quarkus.config.ClientRuntimeConfig} declares the property
 * keys and {@link de.cuioss.sheriff.token.client.quarkus.config.ClientConfigMapper} maps the
 * configured values to the framework-agnostic {@code ClientConfiguration}. Configuration is read
 * directly through MicroProfile {@code Config} (not a {@code @ConfigMapping} interface) so the
 * surface stays native-image-safe and never fails eagerly when the extension is present but unused.
 * <p>
 * All properties are prefixed with {@code sheriff.client}.
 *
 * @author Oliver Wolff
 */
package de.cuioss.sheriff.token.client.quarkus.config;
