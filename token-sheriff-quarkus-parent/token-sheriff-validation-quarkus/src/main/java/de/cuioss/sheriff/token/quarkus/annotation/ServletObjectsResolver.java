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
package de.cuioss.sheriff.token.quarkus.annotation;

import jakarta.inject.Qualifier;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * CDI qualifier for the Vertx-based servlet objects resolver.
 *
 * <p>This qualifier identifies the {@code HttpRequestResolver} implementation
 * that uses Quarkus Vertx {@code HttpServerRequest} to access HTTP context.</p>
 *
 * <p>Usage example:</p>
 * <pre>{@code
 * @Inject
 * @ServletObjectsResolver
 * HttpRequestResolver resolver;
 * }</pre>
 *
 * @since 1.0
 * @author Oliver Wolff
 */
@Qualifier
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.TYPE})
public @interface ServletObjectsResolver {
}