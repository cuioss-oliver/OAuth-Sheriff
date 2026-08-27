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
package de.cuioss.sheriff.token.validation.dpop;

import com.dslplatform.json.DslJson;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter;
import de.cuioss.sheriff.token.commons.events.SecurityEventCounter.EventType;
import de.cuioss.sheriff.token.commons.transport.JwkKey;
import de.cuioss.sheriff.token.commons.transport.ParserConfig;
import de.cuioss.sheriff.token.validation.IssuerConfig;
import de.cuioss.sheriff.token.validation.JWTValidationLogMessages;
import de.cuioss.sheriff.token.validation.domain.context.AccessTokenRequest;
import de.cuioss.sheriff.token.validation.exception.TokenValidationException;
import de.cuioss.sheriff.token.validation.json.MapRepresentation;
import de.cuioss.sheriff.token.validation.jwks.key.JwkKeyHandler;
import de.cuioss.sheriff.token.validation.pipeline.DecodedJwt;
import de.cuioss.sheriff.token.validation.pipeline.SignatureTemplateManager;
import de.cuioss.sheriff.token.validation.pipeline.SignatureVerificationUtil;
import de.cuioss.sheriff.token.validation.security.SignatureAlgorithmPreferences;
import de.cuioss.sheriff.token.validation.util.JwkThumbprintUtil;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.logging.LogRecord;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Validates DPoP (Demonstrating Proof of Possession) proofs per RFC 9449.
 * <p>
 * This validator checks:
 * <ol>
 *   <li>Presence of the DPoP HTTP header</li>
 *   <li>Extraction of {@code cnf.jkt} from the access token</li>
 *   <li>DPoP proof JWT structure (typ, alg, jwk)</li>
 *   <li>DPoP proof signature using embedded JWK</li>
 *   <li>jti uniqueness (replay protection)</li>
 *   <li>iat freshness check</li>
 *   <li>ath (access token hash) match</li>
 *   <li>JWK Thumbprint match against cnf.jkt</li>
 * </ol>
 * <p>
 * DPoP proof JWTs are decoded manually (not via {@code NonValidatingJwtParser})
 * because the DPoP proof header contains {@code jwk} as a nested JSON object,
 * while DSL-JSON's {@code JwtHeader} expects it as a String.
 *
 * @since 1.0
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449">RFC 9449</a>
 */
public class DpopProofValidator {

    private static final CuiLogger LOGGER = new CuiLogger(DpopProofValidator.class);
    private static final String DPOP_HEADER_NAME = "dpop";
    private static final String DPOP_TYP = "dpop+jwt";

    private final DpopConfig config;
    private final int clockSkewSeconds;
    private final SecurityEventCounter securityEventCounter;
    private final DpopReplayProtection replayProtection;
    private final SignatureAlgorithmPreferences algorithmPreferences;
    private final SignatureTemplateManager signatureTemplateManager;
    private final ParserConfig parserConfig;
    private final DslJson<Object> dslJson;

    /**
     * Holds the decoded parts of a DPoP proof JWT.
     *
     * @param parts     the three Base64url-encoded JWT parts (header, payload, signature)
     * @param headerMap the decoded JWT header as a map
     * @param bodyMap   the decoded JWT payload as a map
     */
    private record DecodedDpopProof(List<String> parts, MapRepresentation headerMap, MapRepresentation bodyMap) {
    }

    /**
     * Creates a new DpopProofValidator.
     *
     * @param issuerConfig            the issuer configuration (must have non-null dpopConfig)
     * @param securityEventCounter    the security event counter
     * @param replayProtection        shared replay protection instance
     * @param signatureTemplateManager shared signature template manager (reused across validators)
     * @param parserConfig            shared ParserConfig whose token/payload size bounds are applied to the DPoP proof
     * @param dslJson                 shared DslJson instance from ParserConfig
     */
    public DpopProofValidator(IssuerConfig issuerConfig,
            SecurityEventCounter securityEventCounter,
            DpopReplayProtection replayProtection,
            SignatureTemplateManager signatureTemplateManager,
            ParserConfig parserConfig,
            DslJson<Object> dslJson) {
        this.config = issuerConfig.getDpopConfig();
        this.clockSkewSeconds = issuerConfig.getClockSkewSeconds();
        this.securityEventCounter = securityEventCounter;
        this.replayProtection = replayProtection;
        this.algorithmPreferences = issuerConfig.getAlgorithmPreferences();
        this.signatureTemplateManager = signatureTemplateManager;
        this.parserConfig = parserConfig;
        this.dslJson = dslJson;
    }

    /**
     * Validates the DPoP proof for an access token request.
     *
     * @param request        the access token request containing HTTP headers
     * @param accessTokenJwt the decoded access token JWT
     * @param rawAccessToken the raw access token string (for ath computation)
     * @throws TokenValidationException if DPoP validation fails
     */
    public void validate(AccessTokenRequest request, DecodedJwt accessTokenJwt, String rawAccessToken) {
        String dpopProofString = extractDpopHeader(request);
        Optional<String> cnfJkt = extractCnfJkt(accessTokenJwt);

        if (dpopProofString == null) {
            if (config.isRequired()) {
                // DPoP is required: reject regardless of cnf.jkt
                if (cnfJkt.isPresent()) {
                    rejectWith(EventType.DPOP_PROOF_MISSING, JWTValidationLogMessages.WARN.DPOP_PROOF_MISSING,
                            "DPoP proof is required but the DPoP HTTP header is missing");
                } else {
                    rejectWith(EventType.DPOP_CNF_MISSING, JWTValidationLogMessages.WARN.DPOP_CNF_MISSING,
                            "DPoP is required but access token does not contain cnf.jkt claim");
                }
            }
            // Not required: check if access token has cnf.jkt binding
            if (cnfJkt.isPresent()) {
                rejectWith(EventType.DPOP_PROOF_MISSING, JWTValidationLogMessages.WARN.DPOP_PROOF_MISSING,
                        "DPoP proof is required but the DPoP HTTP header is missing");
            }
            // No cnf.jkt and not required -> bearer mode, no-op
            return;
        }

        // cnf.jkt must be present if DPoP header is provided
        if (cnfJkt.isEmpty()) {
            rejectWith(EventType.DPOP_CNF_MISSING, JWTValidationLogMessages.WARN.DPOP_CNF_MISSING,
                    "DPoP is required but access token does not contain cnf.jkt claim");
        }
        String expectedThumbprint = cnfJkt.get();

        DecodedDpopProof decoded = decodeDpopProofJwt(dpopProofString);
        validateDpopProofHeaderAndSignature(decoded, expectedThumbprint, rawAccessToken, request);
    }

    /**
     * Extracts and validates the DPoP proof string from the HTTP request headers.
     * <p>
     * RFC 9449 Section 7 requires the DPoP header to be single-valued.
     *
     * @param request the access token request containing HTTP headers
     * @return the DPoP proof string, or {@code null} if the header is absent
     * @throws TokenValidationException if multiple DPoP headers are present or the proof exceeds the size limit
     */
    private String extractDpopHeader(AccessTokenRequest request) {
        // HTTP header names are case-insensitive (RFC 9110). Look the DPoP header up case-insensitively
        // so a client that sends "DPoP" (the canonical RFC 9449 casing) is honored and cannot be
        // silently downgraded to bearer mode by a case mismatch (M4). AccessTokenRequest already stores
        // headers in a case-insensitive map; this lookup is defense-in-depth for maps built elsewhere.
        List<String> dpopHeaders = getHeaderIgnoreCase(request.httpHeaders(), DPOP_HEADER_NAME);
        if (dpopHeaders.isEmpty()) {
            return null;
        }
        if (dpopHeaders.size() > 1) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "Multiple DPoP headers found; RFC 9449 requires exactly one");
        }
        String dpopProofString = dpopHeaders.getFirst();
        if (dpopProofString != null && dpopProofString.length() > parserConfig.getMaxTokenSize()) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "DPoP proof exceeds maximum size of %s bytes".formatted(parserConfig.getMaxTokenSize()));
        }
        return dpopProofString;
    }

    /**
     * Looks a header up case-insensitively, tolerating any header-name casing (RFC 9110).
     *
     * @param headers the HTTP header map
     * @param name    the canonical header name to resolve
     * @return the header values, or an empty list if no matching header is present
     */
    private static List<String> getHeaderIgnoreCase(Map<String, List<String>> headers, String name) {
        List<String> direct = headers.get(name);
        if (direct != null) {
            return direct;
        }
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (name.equalsIgnoreCase(entry.getKey())) {
                return entry.getValue();
            }
        }
        return List.of();
    }

    /**
     * Extracts the {@code cnf.jkt} (confirmation key thumbprint) from the access token payload.
     *
     * @param accessTokenJwt the decoded access token JWT
     * @return an {@link Optional} containing the JWK thumbprint, or empty if not present
     */
    private Optional<String> extractCnfJkt(DecodedJwt accessTokenJwt) {
        return accessTokenJwt.body().getNestedMap("cnf")
                .flatMap(cnf -> cnf.getString("jkt"));
    }

    /**
     * Decodes and structurally validates a DPoP proof JWT string.
     * <p>
     * Validates that the JWT has exactly three parts and that the {@code typ} header is
     * {@code dpop+jwt} (case-insensitive). Does not verify the signature.
     * <p>
     * Note: {@code NonValidatingJwtParser} cannot be used here because the DPoP proof
     * header contains {@code jwk} as a nested JSON object, while DSL-JSON's
     * {@code JwtHeader} expects it as a String.
     *
     * @param dpopProofString the raw DPoP proof JWT string
     * @return the decoded header map, payload map, and raw parts
     * @throws TokenValidationException if the JWT structure is invalid or cannot be decoded
     */
    private DecodedDpopProof decodeDpopProofJwt(String dpopProofString) {
        String[] parts = dpopProofString.split("\\.");
        if (parts.length != 3) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "DPoP proof must have 3 parts (header.payload.signature) but has %s".formatted(parts.length));
        }

        MapRepresentation headerMap;
        MapRepresentation bodyMap;
        try {
            byte[] headerBytes = Base64.getUrlDecoder().decode(parts[0]);
            byte[] bodyBytes = Base64.getUrlDecoder().decode(parts[1]);
            int maxPayloadSize = parserConfig.getMaxPayloadSize();
            if (headerBytes.length > maxPayloadSize || bodyBytes.length > maxPayloadSize) {
                rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                        "DPoP proof decoded part exceeds the configured maximum payload size of %s bytes"
                                .formatted(maxPayloadSize));
            }
            headerMap = MapRepresentation.fromJson(dslJson, headerBytes);
            bodyMap = MapRepresentation.fromJson(dslJson, bodyBytes);
        } catch (IllegalArgumentException | IOException e) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "Failed to decode DPoP proof JWT: %s".formatted(e.getMessage()));
            return null; // unreachable but needed for compilation
        }

        // Validate typ header: must be dpop+jwt (case-insensitive)
        String typ = headerMap.getString("typ").orElse(null);
        if (typ == null || !DPOP_TYP.equalsIgnoreCase(typ)) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "DPoP proof typ must be '%s' but was '%s'".formatted(DPOP_TYP, typ));
        }

        return new DecodedDpopProof(List.of(parts), headerMap, bodyMap);
    }

    /**
     * Validates the DPoP proof header fields (alg, jwk), verifies the signature,
     * validates claims, and checks the JWK thumbprint against the expected value.
     */
    private void validateDpopProofHeaderAndSignature(DecodedDpopProof decoded, String expectedThumbprint,
            String rawAccessToken, AccessTokenRequest request) {
        MapRepresentation headerMap = decoded.headerMap();

        // Validate alg header: must be asymmetric
        String alg = headerMap.getString("alg").orElse(null);
        if (alg == null || !algorithmPreferences.isSupported(alg)) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "DPoP proof algorithm '%s' is not supported".formatted(alg));
        }

        // Extract embedded jwk from DPoP proof header
        Optional<Map<String, Object>> jwkOpt = headerMap.getMap("jwk");
        if (jwkOpt.isEmpty()) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "DPoP proof header is missing required 'jwk' field");
        }
        Map<String, Object> jwkMap = jwkOpt.get();
        PublicKey proofPublicKey = parsePublicKey(jwkMap);

        // Validate DPoP proof signature
        verifyDpopSignature(decoded.parts().toArray(String[]::new), proofPublicKey, alg);

        validateDpopClaims(decoded.bodyMap(), rawAccessToken, request);

        // Validate JWK Thumbprint
        String computedThumbprint = JwkThumbprintUtil.computeThumbprint(jwkMap);
        if (!computedThumbprint.equals(expectedThumbprint)) {
            LOGGER.warn(JWTValidationLogMessages.WARN.DPOP_THUMBPRINT_MISMATCH, computedThumbprint, expectedThumbprint);
            securityEventCounter.increment(EventType.DPOP_THUMBPRINT_MISMATCH);
            throw new TokenValidationException(EventType.DPOP_THUMBPRINT_MISMATCH,
                    "DPoP proof JWK thumbprint '%s' does not match token cnf.jkt '%s'"
                            .formatted(computedThumbprint, expectedThumbprint));
        }

        LOGGER.debug("DPoP proof validation successful");
    }

    /**
     * Validates the {@code jti}, {@code iat}, {@code ath}, {@code htu}, and {@code htm} claims
     * of a DPoP proof JWT payload per RFC 9449.
     *
     * @param bodyMap        the decoded DPoP proof payload
     * @param rawAccessToken the raw access token string used to verify the {@code ath} claim
     * @param request        the access token request containing HTTP context for htu/htm validation
     * @throws TokenValidationException if any claim is missing, invalid, or fails validation
     */
    private void validateDpopClaims(MapRepresentation bodyMap, String rawAccessToken, AccessTokenRequest request) {
        // Validate jti (replay protection)
        Optional<String> jti = bodyMap.getString("jti");
        if (jti.isEmpty()) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_MISSING_CLAIM,
                    "DPoP proof is missing required claim: jti");
        }
        if (!replayProtection.checkAndStore(jti.get())) {
            LOGGER.warn(JWTValidationLogMessages.WARN.DPOP_REPLAY_DETECTED, jti.get());
            securityEventCounter.increment(EventType.DPOP_REPLAY_DETECTED);
            throw new TokenValidationException(EventType.DPOP_REPLAY_DETECTED,
                    "DPoP proof replay detected for jti: %s".formatted(jti.get()));
        }

        // Validate iat (freshness)
        Optional<Number> iat = bodyMap.getNumber("iat");
        if (iat.isEmpty()) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_MISSING_CLAIM,
                    "DPoP proof is missing required claim: iat");
        }
        long iatSeconds = iat.get().longValue();
        long nowSeconds = System.currentTimeMillis() / 1000;
        long age = nowSeconds - iatSeconds;
        if (age < -clockSkewSeconds || age > config.getProofMaxAgeSeconds()) {
            LOGGER.warn(JWTValidationLogMessages.WARN.DPOP_PROOF_EXPIRED);
            securityEventCounter.increment(EventType.DPOP_PROOF_EXPIRED);
            throw new TokenValidationException(EventType.DPOP_PROOF_EXPIRED,
                    "DPoP proof iat claim is outside acceptable freshness window");
        }

        // Validate ath (access token hash)
        Optional<String> ath = bodyMap.getString("ath");
        if (ath.isEmpty()) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_MISSING_CLAIM,
                    "DPoP proof is missing required claim: ath");
        }
        String expectedAth = computeAccessTokenHash(rawAccessToken);
        if (!expectedAth.equals(ath.get())) {
            LOGGER.warn(JWTValidationLogMessages.WARN.DPOP_ATH_MISMATCH);
            securityEventCounter.increment(EventType.DPOP_ATH_MISMATCH);
            throw new TokenValidationException(EventType.DPOP_ATH_MISMATCH,
                    "DPoP proof ath claim does not match access token hash");
        }

        // Validate htm and htu (RFC 9449 Section 4.3)
        validateHtuHtm(bodyMap, request);
    }

    /**
     * Validates the {@code htu} (HTTP URI) and {@code htm} (HTTP method) claims of the DPoP proof
     * against the actual HTTP request per RFC 9449 Section 4.3.
     * <p>
     * If the request does not carry URI/method information, validation is skipped with a WARN log.
     * The {@code htu} comparison strips query string and fragment per RFC 9449.
     */
    private void validateHtuHtm(MapRepresentation bodyMap, AccessTokenRequest request) {
        if (request.requestUri() == null || request.requestUri().isBlank()
                || request.requestMethod() == null || request.requestMethod().isBlank()) {
            // When a DPoP proof is present, htu/htm validation must not be skipped —
            // a proof valid for a different endpoint would be accepted otherwise.
            securityEventCounter.increment(EventType.DPOP_PROOF_INVALID);
            throw new TokenValidationException(EventType.DPOP_PROOF_INVALID,
                    "DPoP htu/htm validation failed: request URI and method are required when a DPoP proof is present");
        }

        // Validate htm (HTTP method)
        Optional<String> htm = bodyMap.getString("htm");
        if (htm.isEmpty()) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_MISSING_CLAIM,
                    "DPoP proof is missing required claim: htm");
        }
        if (!request.requestMethod().equalsIgnoreCase(htm.get())) {
            LOGGER.warn(JWTValidationLogMessages.WARN.DPOP_HTM_MISMATCH, htm.get(), request.requestMethod());
            securityEventCounter.increment(EventType.DPOP_HTM_MISMATCH);
            throw new TokenValidationException(EventType.DPOP_HTM_MISMATCH,
                    "DPoP proof htm claim '%s' does not match request method '%s'"
                            .formatted(htm.get(), request.requestMethod()));
        }

        // Validate htu (HTTP URI) — strip query and fragment per RFC 9449
        Optional<String> htu = bodyMap.getString("htu");
        if (htu.isEmpty()) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_MISSING_CLAIM,
                    "DPoP proof is missing required claim: htu");
        }
        String normalizedHtu = stripQueryAndFragment(htu.get());
        String normalizedRequestUri = stripQueryAndFragment(request.requestUri());
        if (!normalizedHtu.equals(normalizedRequestUri)) {
            LOGGER.warn(JWTValidationLogMessages.WARN.DPOP_HTU_MISMATCH, htu.get(), request.requestUri());
            securityEventCounter.increment(EventType.DPOP_HTU_MISMATCH);
            throw new TokenValidationException(EventType.DPOP_HTU_MISMATCH,
                    "DPoP proof htu claim '%s' does not match request URI '%s'"
                            .formatted(htu.get(), request.requestUri()));
        }
    }

    /**
     * Normalizes a URI for {@code htu} comparison per RFC 9449 §4.3 and RFC 3986 §6.
     * <p>
     * Beyond stripping the query string and fragment, this lower-cases the scheme and host
     * (case-insensitive per RFC 3986 §6.2.2.1), strips the default port for {@code http} (80)
     * and {@code https} (443) (§6.2.3), and resolves dot-segments in the path via
     * {@link URI#normalize()} (§6.2.2.3), so that syntactically different but semantically
     * equivalent URIs compare equal and cannot be used to bypass the {@code htu} check.
     */
    private static String stripQueryAndFragment(String uri) {
        try {
            var parsed = new URI(uri).normalize();
            String host = parsed.getHost();
            if (host == null) {
                // Opaque or registry-based authority — cannot safely decompose host/port;
                // fall back to scheme/authority/path with query and fragment stripped.
                return new URI(lowerCaseOrNull(parsed.getScheme()), parsed.getAuthority(),
                        parsed.getPath(), null, null).toString();
            }
            String scheme = lowerCaseOrNull(parsed.getScheme());
            int port = parsed.getPort();
            if (("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443)) {
                port = -1;
            }
            return new URI(scheme, parsed.getUserInfo(), host.toLowerCase(Locale.ROOT), port,
                    parsed.getPath(), null, null).toString();
        } catch (URISyntaxException e) {
            // If URI is malformed, return as-is and let comparison fail
            return uri;
        }
    }

    private static String lowerCaseOrNull(String value) {
        return value == null ? null : value.toLowerCase(Locale.ROOT);
    }

    private PublicKey parsePublicKey(Map<String, Object> jwkMap) {
        MapRepresentation jwkRep = new MapRepresentation(jwkMap);
        String kty = jwkRep.getString("kty").orElse(null);
        if (kty == null) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "DPoP proof JWK is missing required 'kty' field or it is not a string");
        }

        try {
            // Create a JwkKey from the map using type-safe accessors
            JwkKey jwkKey = new JwkKey(
                    kty,
                    jwkRep.getString("kid").orElse(null),
                    jwkRep.getString("alg").orElse(null),
                    jwkRep.getString("n").orElse(null),
                    jwkRep.getString("e").orElse(null),
                    jwkRep.getString("crv").orElse(null),
                    jwkRep.getString("x").orElse(null),
                    jwkRep.getString("y").orElse(null)
            );

            return switch (kty) {
                // Sub-2048-bit RSA keys (M1) are rejected inside JwkKeyHandler.parseRsaKey, which throws
                // InvalidKeySpecException ("RSA key modulus is %d bits; minimum accepted is %d bits"); the
                // catch block below converts that into the same DPOP_PROOF_INVALID rejection, so no
                // duplicate pre-check is needed here.
                case "RSA" -> JwkKeyHandler.parseRsaKey(jwkKey);
                case "EC" -> JwkKeyHandler.parseEcKey(jwkKey);
                case "OKP" -> JwkKeyHandler.parseOkpKey(jwkKey);
                default -> {
                    rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                            "Unsupported DPoP proof key type: %s".formatted(kty));
                    yield null; // unreachable
                }
            };
        } catch (InvalidKeySpecException e) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "Failed to parse DPoP proof public key: %s".formatted(e.getMessage()));
            return null; // unreachable
        }
    }

    private void verifyDpopSignature(String[] parts, PublicKey publicKey, String algorithm) {
        try {
            String dataToVerify = parts[0] + "." + parts[1];
            byte[] dataBytes = dataToVerify.getBytes(StandardCharsets.UTF_8);
            byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);

            if (!SignatureVerificationUtil.verifySignature(
                    signatureTemplateManager, publicKey, algorithm, dataBytes, signatureBytes)) {
                rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                        "DPoP proof signature verification failed");
            }
        } catch (InvalidKeyException | SignatureException e) {
            rejectWith(EventType.DPOP_PROOF_INVALID, JWTValidationLogMessages.WARN.DPOP_PROOF_INVALID,
                    "DPoP proof signature verification failed: %s".formatted(e.getMessage()));
        }
    }

    private String computeAccessTokenHash(String rawAccessToken) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(rawAccessToken.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private void rejectWith(EventType eventType,
            LogRecord logRecord, String message) {
        LOGGER.warn(logRecord, message);
        securityEventCounter.increment(eventType);
        throw new TokenValidationException(eventType, message);
    }
}
