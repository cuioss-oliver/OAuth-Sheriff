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
import java.util.Objects;

/**
 * {@code client_secret_post} client authentication (RFC 6749 §2.3.1): the client id and secret are
 * sent in the form-encoded request body over TLS. The secret is never placed in a URL and never
 * logged.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public class ClientSecretPostAuth implements ClientAuthentication {

    private static final String PARAM_CLIENT_ID = "client_id";
    private static final String PARAM_CLIENT_SECRET = "client_secret";

    private final String clientId;
    private final String clientSecret;

    /**
     * @param clientId     the OAuth 2.0 client id; must not be {@code null}
     * @param clientSecret the shared client secret; must not be {@code null}
     */
    public ClientSecretPostAuth(String clientId, String clientSecret) {
        this.clientId = Objects.requireNonNull(clientId, "clientId must not be null");
        this.clientSecret = Objects.requireNonNull(clientSecret, "clientSecret must not be null");
    }

    @Override
    public ClientAuthMethod method() {
        return ClientAuthMethod.CLIENT_SECRET_POST;
    }

    @Override
    public void decorate(Map<String, String> formParameters, Map<String, String> requestHeaders) {
        formParameters.put(PARAM_CLIENT_ID, clientId);
        formParameters.put(PARAM_CLIENT_SECRET, clientSecret);
    }
}
