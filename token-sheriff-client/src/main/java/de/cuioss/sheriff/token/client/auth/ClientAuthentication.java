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
package de.cuioss.sheriff.token.client.auth;

import de.cuioss.sheriff.token.client.config.ClientAuthMethod;

import java.util.Map;

/**
 * Strategy for authenticating the client on an authenticated back-channel request — the token,
 * pushed-authorization-request, revocation, or introspection endpoint.
 * <p>
 * An implementation decorates the outgoing request by adding request headers and/or form
 * parameters. Credentials are only ever placed in an HTTP header or the form-encoded body — never
 * in a URL. Transport-bound methods (mutual TLS) authenticate at the TLS layer and only identify
 * the client in the request.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.3">RFC 6749 §2.3 - Client Authentication</a>
 */
public interface ClientAuthentication {

    /**
     * @return the authentication method this strategy implements
     */
    ClientAuthMethod method();

    /**
     * Decorates the outgoing back-channel request with this client authentication.
     *
     * @param formParameters the mutable form-encoded request-body parameters
     * @param requestHeaders the mutable request headers
     */
    void decorate(Map<String, String> formParameters, Map<String, String> requestHeaders);
}
