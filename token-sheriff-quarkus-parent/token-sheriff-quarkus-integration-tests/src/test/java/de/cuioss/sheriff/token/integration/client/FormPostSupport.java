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
package de.cuioss.sheriff.token.integration.client;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.StringJoiner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses the OAuth 2.0 {@code response_mode=form_post} auto-submit document Keycloak returns after a
 * successful login (OAuth 2.0 Form Post Response Mode).
 * <p>
 * The {@code C1} fix emits {@code response_mode=form_post} on the authorization request, so a successful
 * login no longer 302-redirects with the authorization-response parameters in the {@code Location} query.
 * Keycloak instead returns HTTP 200 with an auto-submitting HTML form whose {@code action} is the
 * registered {@code redirect_uri} and whose hidden inputs carry the authorization-response parameters
 * ({@code code}, {@code state}, and the RFC 9207 {@code iss}). This helper reduces that document back to
 * the {@code action} target and a URL-encoded callback query string ({@code key=value&...}) equivalent to
 * the query the client callback would have received from a 302 redirect — so the client-flow callers can
 * keep parsing the callback with {@code CallbackParameters.parse(...)} unchanged.
 * <p>
 * Only the {@code code}, {@code state}, and {@code iss} inputs are carried through; any other hidden
 * inputs Keycloak emits (e.g. {@code session_state}) are dropped, matching the parameters the client flow
 * consumes and avoiding a spurious duplicate-parameter rejection.
 */
final class FormPostSupport {

    /** First {@code <form ... action="...">} target in the document — the callback {@code redirect_uri}. */
    private static final Pattern FORM_ACTION =
            Pattern.compile("<form[^>]*\\baction=\"([^\"]*)\"", Pattern.CASE_INSENSITIVE);

    /**
     * A hidden {@code <input name="..." value="...">}. Keycloak's form_post template renders
     * {@code name} before {@code value} on every input; {@code [^>]*} never crosses the tag boundary,
     * so name and value are always read from the same tag.
     */
    private static final Pattern HIDDEN_INPUT =
            Pattern.compile("<input\\b[^>]*\\bname=\"([^\"]*)\"[^>]*\\bvalue=\"([^\"]*)\"[^>]*>",
                    Pattern.CASE_INSENSITIVE);

    /** The authorization-response parameters the client flow consumes from the callback. */
    private static final Set<String> CALLBACK_PARAMS = Set.of("code", "state", "iss");

    private FormPostSupport() {
        // utility class
    }

    /**
     * The reduced form_post callback: the form {@code action} target and the URL-encoded callback query.
     *
     * @param action the form {@code action} target (the callback {@code redirect_uri})
     * @param query  the URL-encoded {@code key=value&...} callback query string
     */
    record FormPost(String action, String query) {
    }

    /**
     * Parses a form_post auto-submit document into its {@link FormPost} projection.
     *
     * @param body the HTML body of the form_post response; must not be {@code null}
     * @return the parsed form action and callback query string
     * @throws IllegalStateException if the document exposes no form action
     */
    static FormPost parse(String body) {
        Matcher action = FORM_ACTION.matcher(body);
        if (!action.find()) {
            throw new IllegalStateException("form_post document does not expose a form action");
        }
        String formAction = htmlUnescape(action.group(1));

        StringJoiner query = new StringJoiner("&");
        Matcher input = HIDDEN_INPUT.matcher(body);
        while (input.find()) {
            String name = input.group(1);
            if (CALLBACK_PARAMS.contains(name)) {
                query.add(encode(name) + "=" + encode(htmlUnescape(input.group(2))));
            }
        }
        return new FormPost(formAction, query.toString());
    }

    /**
     * Reverses the HTML-attribute escaping Keycloak applies to hidden-input values, restoring the raw
     * parameter value before it is re-encoded for the callback query. {@code &amp;} is reversed last so
     * an already-unescaped ampersand cannot be double-decoded.
     */
    private static String htmlUnescape(String value) {
        return value
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&#39;", "'")
                .replace("&#x27;", "'")
                .replace("&#x3D;", "=")
                .replace("&#61;", "=")
                .replace("&amp;", "&");
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
