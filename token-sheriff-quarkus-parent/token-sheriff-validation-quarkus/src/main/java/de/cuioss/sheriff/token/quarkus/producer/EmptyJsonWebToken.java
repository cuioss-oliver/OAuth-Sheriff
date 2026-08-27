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

import org.eclipse.microprofile.jwt.JsonWebToken;

import java.util.Set;

/**
 * An empty {@link JsonWebToken} implementation injected when no valid JWT is present
 * in the current request.
 * <p>
 * Per the MicroProfile JWT Auth specification: "If there is no JWT in the request,
 * an empty JsonWebToken is injected, which means all method calls to this token return null."
 * <p>
 * This is a singleton — use {@link #INSTANCE}.
 *
 * @since 1.0
 */
@SuppressWarnings("java:S6548") // Singleton is intentional — single "no token" sentinel per MP-JWT spec
final class EmptyJsonWebToken implements JsonWebToken {

    static final EmptyJsonWebToken INSTANCE = new EmptyJsonWebToken();

    private EmptyJsonWebToken() {
    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public Set<String> getClaimNames() {
        return Set.of();
    }

    @Override
    public <T> T getClaim(String claimName) {
        return null;
    }
}
