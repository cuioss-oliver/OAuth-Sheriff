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
package de.cuioss.sheriff.token.commons.transport;

import com.dslplatform.json.DslJson;
import de.cuioss.http.client.ContentType;
import de.cuioss.http.client.converter.StringContentConverter;
import de.cuioss.tools.logging.CuiLogger;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Optional;


/**
 * HTTP content converter for JSON Web Key Set (JWKS) content.
 * <p>
 * This converter handles the transformation of HTTP String responses
 * containing JWKS JSON data into Jwks objects using DSL-JSON for
 * high-performance parsing.
 * <p>
 * The converter is thread-safe and reusable across multiple HTTP requests.
 * It follows the CUI converter pattern by extending StringContentConverter
 * and provides proper empty value semantics for error cases.
 * <p>
 * A byte ceiling ({@link ParserConfig#getMaxPayloadSize()}) is enforced on the JWKS body while it
 * streams (see {@link BoundedBodyHandlers}), so an oversized key set is rejected before it is fully
 * buffered rather than being read unbounded into memory (H2). Both the streaming rejection and the
 * post-materialization rejection report the enforced bound together with its origin — the
 * {@code ParserConfig.maxPayloadSize} knob and how to set it — so a reader of the failure knows
 * which setting produced the ceiling.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public class JwksHttpContentConverter extends StringContentConverter<Jwks> {

    private static final CuiLogger LOGGER = new CuiLogger(JwksHttpContentConverter.class);

    /**
     * Human-readable provenance of the JWKS byte ceiling, reported with every over-limit rejection
     * so a reader knows which knob produced the bound and that it is settable.
     */
    private static final String BOUND_ORIGIN =
            "ParserConfig.maxPayloadSize; settable via ParserConfig.builder().maxPayloadSize(...)";

    private final DslJson<Object> dslJson;
    private final int maxContentSize;

    /**
     * Creates a new JWKS content converter with specified parser configuration.
     *
     * @param parserConfig the parser configuration to use for DSL-JSON
     */
    public JwksHttpContentConverter(ParserConfig parserConfig) {
        super(StandardCharsets.UTF_8);
        this.dslJson = parserConfig.getDslJson();
        this.maxContentSize = parserConfig.getMaxPayloadSize();
    }

    @Override
    public HttpResponse.BodyHandler<?> getBodyHandler() {
        // Bound the JWKS body during streaming so an oversized response fails closed before it is
        // fully materialized. The size check in convertString(...) remains as defense in depth.
        return BoundedBodyHandlers.ofBoundedString(StandardCharsets.UTF_8, maxContentSize, BOUND_ORIGIN);
    }

    @Override
    protected Optional<Jwks> convertString(String rawContent) {
        if (rawContent == null || rawContent.trim().isEmpty()) {
            LOGGER.debug("Empty or null JWKS content received");
            return Optional.empty();
        }

        byte[] bodyBytes = rawContent.getBytes(StandardCharsets.UTF_8);
        if (bodyBytes.length > maxContentSize) {
            String overLimitMessage = "JWKS response size exceeds maximum allowed size of "
                    + maxContentSize + " bytes (" + BOUND_ORIGIN + ")";
            LOGGER.warn(TransportLogMessages.WARN.JWKS_JSON_PARSE_FAILED, overLimitMessage);
            return Optional.empty();
        }

        try {
            Jwks jwks = dslJson.deserialize(Jwks.class, bodyBytes, bodyBytes.length);

            if (jwks == null) {
                LOGGER.warn(TransportLogMessages.WARN.JWKS_PARSE_NULL_RESULT);
                return Optional.empty();
            }

            LOGGER.debug("Successfully parsed JWKS with %s keys",
                    jwks.keys() != null ? jwks.keys().size() : 0);
            return Optional.of(jwks);

        } catch (IOException e) {
            LOGGER.warn(TransportLogMessages.WARN.JWKS_PARSE_IO_ERROR, e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public ContentType contentType() {
        return ContentType.APPLICATION_JSON;
    }
}