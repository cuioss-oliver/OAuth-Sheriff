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
package de.cuioss.sheriff.token.client.flow;

import com.dslplatform.json.CompiledJson;
import com.dslplatform.json.JsonAttribute;

import java.util.Optional;

/**
 * The normalized RFC 9126 pushed-authorization-request (PAR) endpoint response.
 * <p>
 * Produced by {@link ParClient} from a successful PAR {@code POST}. The authorization server stores
 * the pushed parameters and returns an opaque, single-use {@code request_uri} plus its lifetime in
 * seconds; the front-channel authorization redirect then carries only that {@code request_uri} (and
 * the {@code client_id}), never the raw authorization parameters ({@code T-PARAM-INTEGRITY}).
 * <p>
 * Parsing uses DSL-JSON's compile-time {@code @CompiledJson} mapping. Fields are {@code public}
 * because DSL-JSON class-based deserialization requires it; after deserialization the object is
 * treated as read-only and callers should use the accessor methods.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 */
@CompiledJson
@SuppressWarnings("java:S1104") // Public fields required by DSL-JSON @CompiledJson for class-based deserialization
public class ParResponse {

    /** The opaque, single-use request URI to carry on the front-channel authorization redirect. */
    @JsonAttribute(name = "request_uri")
    public String requestUri;

    /** The request-URI lifetime in seconds, or {@code 0} when the AS omits it. */
    @JsonAttribute(name = "expires_in")
    public long expiresIn;

    /**
     * @return the pushed-authorization {@code request_uri}, or {@link Optional#empty()} if absent
     */
    public Optional<String> getRequestUri() {
        return Optional.ofNullable(requestUri);
    }

    /**
     * @return the {@code request_uri} lifetime in seconds ({@code 0} when omitted)
     */
    public long getExpiresIn() {
        return expiresIn;
    }
}
