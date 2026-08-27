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
 * Build-time (deployment) module of the Quarkus extension for the Token-Sheriff client engine.
 * <p>
 * Holds the {@code io.quarkus.deployment.annotations.BuildStep} processing for the extension. In this
 * wired-but-empty skeleton (Plan 05) it registers the {@code token-sheriff-client} feature; reflection,
 * CDI bean and native-image registration for the client flows land with those flows (Plan 06).
 *
 * @author Oliver Wolff
 * @see de.cuioss.sheriff.token.client.quarkus.deployment.TokenSheriffClientProcessor
 */
package de.cuioss.sheriff.token.client.quarkus.deployment;
