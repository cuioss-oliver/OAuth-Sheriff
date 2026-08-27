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
package de.cuioss.sheriff.token.quarkus.producer;

import de.cuioss.sheriff.token.quarkus.annotation.BearerToken;
import jakarta.enterprise.inject.spi.Annotated;
import jakarta.enterprise.inject.spi.Bean;
import jakarta.enterprise.inject.spi.InjectionPoint;

import java.lang.annotation.Annotation;
import java.lang.reflect.Member;
import java.lang.reflect.Type;
import java.util.Set;

/**
 * Mock InjectionPoint for testing BearerTokenProducer CDI producer method.
 * This class provides a minimal implementation needed for testing purposes.
 */
public class MockInjectionPoint implements InjectionPoint {

    private final BearerToken bearerTokenAnnotation;

    public MockInjectionPoint(Set<String> requiredScopes, Set<String> requiredRoles, Set<String> requiredGroups) {
        this.bearerTokenAnnotation = new BearerToken() {
            @Override
            public Class<? extends Annotation> annotationType() {
                return BearerToken.class;
            }

            @Override
            public String[] requiredScopes() {
                return requiredScopes.toArray(new String[0]);
            }

            @Override
            public String[] requiredRoles() {
                return requiredRoles.toArray(new String[0]);
            }

            @Override
            public String[] requiredGroups() {
                return requiredGroups.toArray(new String[0]);
            }
        };
    }

    /**
     * Constructor for testing null annotation case
     */
    public MockInjectionPoint(BearerToken annotation) {
        this.bearerTokenAnnotation = annotation;
    }

    @Override
    public Type getType() {
        return BearerTokenResult.class;
    }

    @Override
    public Set<Annotation> getQualifiers() {
        return Set.of(bearerTokenAnnotation);
    }

    @Override
    public Bean<?> getBean() {
        return null;
    }

    @Override
    public Member getMember() {
        return null;
    }

    @Override
    public Annotated getAnnotated() {
        return new Annotated() {
            @Override
            public Type getBaseType() {
                return BearerTokenResult.class;
            }

            @Override
            public Set<Type> getTypeClosure() {
                return Set.of(BearerTokenResult.class);
            }

            @Override
            public <T extends Annotation> T getAnnotation(Class<T> annotationType) {
                if (annotationType == BearerToken.class && bearerTokenAnnotation != null) {
                    return annotationType.cast(bearerTokenAnnotation);
                }
                return null;
            }

            @Override
            public <T extends Annotation> Set<T> getAnnotations(Class<T> annotationType) {
                if (annotationType == BearerToken.class) {
                    return Set.of(annotationType.cast(bearerTokenAnnotation));
                }
                return Set.of();
            }

            @Override
            public Set<Annotation> getAnnotations() {
                return Set.of(bearerTokenAnnotation);
            }

            @Override
            public boolean isAnnotationPresent(Class<? extends Annotation> annotationType) {
                return annotationType == BearerToken.class;
            }
        };
    }

    @Override
    public boolean isDelegate() {
        return false;
    }

    @Override
    public boolean isTransient() {
        return false;
    }
}