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
package de.cuioss.sheriff.token.client.token;

import com.dslplatform.json.CompiledJson;
import com.dslplatform.json.JsonAttribute;

import java.util.Optional;

/**
 * The normalized OpenID Connect userinfo response (OIDC Core §5.3.2).
 * <p>
 * Produced by {@link UserInfoClient} from a successful userinfo request. The {@code sub} claim is the
 * identity-critical field: it MUST be bound back to the validated ID token's {@code sub} by
 * {@link SubBindingValidator} before any claim here is trusted — an unsigned userinfo document is
 * transport-authenticated only, so its identity is never taken on its own.
 * <p>
 * Parsing uses DSL-JSON's compile-time {@code @CompiledJson} mapping. Fields are {@code public}
 * because DSL-JSON class-based deserialization requires it; after deserialization the object is
 * treated as read-only and callers should use the accessor methods.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">OIDC Core §5.3.2</a>
 */
@CompiledJson
@SuppressWarnings("java:S1104") // Public fields required by DSL-JSON @CompiledJson for class-based deserialization
public class UserInfoResponse {

    /** The subject identifier — the identity-critical claim bound back to the ID token {@code sub}. */
    public String sub;

    /** The end-user's display name, if released. */
    public String name;

    /** The end-user's email address, if released. */
    public String email;

    /** Whether the email address has been verified by the provider. */
    @JsonAttribute(name = "email_verified")
    public boolean emailVerified;

    /**
     * @return the subject identifier, or {@link Optional#empty()} if absent
     */
    public Optional<String> getSub() {
        return Optional.ofNullable(sub);
    }

    /**
     * @return the display name, or {@link Optional#empty()} if absent
     */
    public Optional<String> getName() {
        return Optional.ofNullable(name);
    }

    /**
     * @return the email address, or {@link Optional#empty()} if absent
     */
    public Optional<String> getEmail() {
        return Optional.ofNullable(email);
    }

    /**
     * @return whether the email address is verified
     */
    public boolean isEmailVerified() {
        return emailVerified;
    }
}
