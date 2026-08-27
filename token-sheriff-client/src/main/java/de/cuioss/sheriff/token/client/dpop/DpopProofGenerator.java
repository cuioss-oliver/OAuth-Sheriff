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
package de.cuioss.sheriff.token.client.dpop;

import de.cuioss.sheriff.token.client.internal.ClientLogMessages;
import de.cuioss.sheriff.token.client.internal.JsonEscaper;
import de.cuioss.sheriff.token.validation.util.EcdsaSignatureFormatConverter;
import de.cuioss.sheriff.token.validation.util.JwkThumbprintUtil;
import de.cuioss.tools.logging.CuiLogger;
import org.jspecify.annotations.Nullable;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.EdECPoint;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Builds RFC 9449 DPoP proof JWTs binding the token request to a client-held proof key.
 * <p>
 * A DPoP proof is a JWT signed by the client's proof key, carrying the target HTTP method
 * ({@code htm}), the target URI ({@code htu}), a unique identifier ({@code jti}), and the issue time
 * ({@code iat}); its header embeds the proof-key's public JWK. Presenting it on the token request
 * makes the authorization server issue an access token bound to the proof key via {@code cnf.jkt}
 * ({@link #jkt()}), so a stolen bearer token cannot be replayed without the private key
 * ({@code CLIENT-11}, {@code T-TOKEN-REPLAY}).
 * <p>
 * The generator signs with a JDK {@link Signature} — the engine adds no cryptographic library of its
 * own — and mirrors the {@code DpopProofHelper} conventions already used by the integration harness.
 * The supported proof-key and algorithm matrix is:
 * <table border="1">
 *   <caption>Supported proof keys and signing algorithms</caption>
 *   <tr><th>Proof key</th><th>Signing algorithms</th></tr>
 *   <tr><td>RSA</td><td>{@code RS256}, {@code RS384}, {@code RS512}, {@code PS256}</td></tr>
 *   <tr><td>EC, curve P-256</td><td>{@code ES256}</td></tr>
 *   <tr><td>OKP, curve Ed25519</td><td>{@code EdDSA}</td></tr>
 * </table>
 * <p>
 * Passing {@code PS256}, {@code ES256} or {@code EdDSA} reaches FAPI 2.0 §5.4.1 conformance through
 * the DPoP route. The algorithm and the proof key are checked against each other at construction
 * time, so a mismatch fails fast rather than surfacing later from the JCA layer.
 * <p>
 * <strong>Replay defence:</strong> every emitted proof carries a fresh, single-use {@code jti}. The
 * generator tracks the identifiers it has issued and fails closed if its {@code jti} source ever
 * repeats a value, so it can never emit two proofs sharing a {@code jti} that an attacker could
 * replay. Instances are safe for concurrent use.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9449">RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7638">RFC 7638 - JSON Web Key (JWK) Thumbprint</a>
 */
public class DpopProofGenerator {

    private static final CuiLogger LOGGER = new CuiLogger(DpopProofGenerator.class);

    /** The DPoP proof JWT header {@code typ}. */
    static final String DPOP_TYP = "dpop+jwt";
    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

    /**
     * Upper bound on the number of recently-issued {@code jti} values tracked for reuse detection.
     * The set is a bounded LRU rather than an unbounded set so a long-lived generator cannot leak
     * memory; reuse is still detected fail-closed within this most-recent window.
     */
    private static final int MAX_TRACKED_JTIS = 10_000;

    private static final String KTY_RSA = "RSA";
    private static final String KTY_EC = "EC";
    private static final String KTY_OKP = "OKP";
    private static final String CRV_P256 = "P-256";
    private static final String CRV_ED25519 = "Ed25519";
    private static final String ALG_PS256 = "PS256";
    private static final String ALG_ES256 = "ES256";

    /** JCA standard name of curve P-256, the only curve an EC proof key may use. */
    private static final String CURVE_SECP256R1 = "secp256r1";

    /**
     * Curve P-256's domain parameters, resolved once from the JCA provider. Every EC proof key is
     * compared against these in full — a field-size check alone would admit any other 256-bit curve
     * (secp256k1, brainpoolP256r1), whose key would then be published in a JWK claiming
     * {@code "crv":"P-256"}: a curve-confusion defect.
     */
    private static final ECParameterSpec P256_PARAMS = resolveP256Params();

    /** Fixed width of a P-256 affine coordinate per RFC 7518 §6.2.1.2. */
    private static final int P256_COORDINATE_BYTES = 32;

    /** Fixed width of an Ed25519 public key per RFC 8032. */
    private static final int ED25519_KEY_BYTES = 32;

    /**
     * The proof-key type ({@code kty}) each supported signing algorithm requires. Consulted at
     * construction time so an algorithm/key mismatch fails fast instead of surfacing from the JCA
     * layer at the first {@code sign()} call.
     */
    private static final Map<String, String> ALGORITHM_KEY_TYPES = Map.of(
            "RS256", KTY_RSA,
            "RS384", KTY_RSA,
            "RS512", KTY_RSA,
            ALG_PS256, KTY_RSA,
            ALG_ES256, KTY_EC,
            "EdDSA", KTY_OKP);

    private final KeyPair keyPair;
    private final String jwtAlgorithm;
    private final String jcaAlgorithm;
    private final String jwkJson;
    private final String jkt;
    private final Supplier<String> jtiSource;
    // Bounded, thread-safe LRU of recently-issued jti values: access-ordered LinkedHashMap that evicts
    // its eldest entry once it exceeds MAX_TRACKED_JTIS, wrapped in a synchronized view for concurrent
    // use. Explicit java.util imports keep the construction stable under OpenRewrite.
    private final Map<String, Boolean> issuedJtis = Collections.synchronizedMap(
            new LinkedHashMap<String, Boolean>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
                    return size() > MAX_TRACKED_JTIS;
                }
            });

    /**
     * Creates a generator that mints a random {@code jti} for every proof.
     *
     * @param keyPair   the proof key pair (RSA, EC P-256 or OKP Ed25519); must not be {@code null}
     * @param algorithm the JWT signing algorithm ({@code RS256} / {@code RS384} / {@code RS512} /
     *                  {@code PS256} / {@code ES256} / {@code EdDSA})
     * @throws IllegalArgumentException if the algorithm is unsupported, the proof key is not an RSA,
     *         EC P-256 or OKP Ed25519 key, or the algorithm does not match the proof-key type
     */
    public DpopProofGenerator(KeyPair keyPair, String algorithm) {
        this(keyPair, algorithm, () -> UUID.randomUUID().toString());
    }

    /**
     * Creates a generator with an explicit {@code jti} source. The overload exists so tests can force
     * a repeated identifier and assert the reuse defence; production code uses the random-{@code jti}
     * constructor above.
     *
     * @param keyPair   the proof key pair (RSA, EC P-256 or OKP Ed25519); must not be {@code null}
     * @param algorithm the JWT signing algorithm ({@code RS256} / {@code RS384} / {@code RS512} /
     *                  {@code PS256} / {@code ES256} / {@code EdDSA})
     * @param jtiSource the source of proof identifiers; must not be {@code null}
     * @throws IllegalArgumentException if the algorithm is unsupported, the proof key is not an RSA,
     *         EC P-256 or OKP Ed25519 key, or the algorithm does not match the proof-key type
     */
    public DpopProofGenerator(KeyPair keyPair, String algorithm, Supplier<String> jtiSource) {
        this.keyPair = Objects.requireNonNull(keyPair, "keyPair must not be null");
        this.jwtAlgorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
        this.jtiSource = Objects.requireNonNull(jtiSource, "jtiSource must not be null");
        this.jcaAlgorithm = toJcaAlgorithm(algorithm);
        // One JWK map feeds both the header 'jwk' and the cnf.jkt thumbprint, so a proof can never
        // advertise a key whose thumbprint does not match the embedded JWK.
        Map<String, Object> jwk = buildJwk(keyPair.getPublic(), algorithm);
        this.jwkJson = JwkThumbprintUtil.canonicalJson(jwk);
        this.jkt = JwkThumbprintUtil.computeThumbprint(jwk);
    }

    /**
     * Classifies the proof key, verifies it matches the requested signing algorithm, and builds the
     * canonical JWK members for its key type.
     *
     * @param publicKey the proof key's public key
     * @param algorithm the requested JWT signing algorithm
     * @return the JWK members required for this key type by RFC 7638
     * @throws IllegalArgumentException if the key type or curve is unsupported, or the algorithm does
     *         not match the key type
     */
    private static Map<String, Object> buildJwk(PublicKey publicKey, String algorithm) {
        if (publicKey instanceof RSAPublicKey rsaKey) {
            requireKeyTypeMatches(algorithm, KTY_RSA);
            return Map.of(
                    "kty", KTY_RSA,
                    "e", base64UrlUnsigned(rsaKey.getPublicExponent()),
                    "n", base64UrlUnsigned(rsaKey.getModulus()));
        }
        if (publicKey instanceof ECPublicKey ecKey) {
            requireKeyTypeMatches(algorithm, KTY_EC);
            requireP256Curve(ecKey.getParams());
            return Map.of(
                    "kty", KTY_EC,
                    "crv", CRV_P256,
                    // RFC 7518 §6.2.1.2: coordinates are left-padded to the full coordinate width,
                    // so base64UrlUnsigned (which strips rather than pads) must not be used here.
                    "x", base64UrlFixedWidth(ecKey.getW().getAffineX(), P256_COORDINATE_BYTES),
                    "y", base64UrlFixedWidth(ecKey.getW().getAffineY(), P256_COORDINATE_BYTES));
        }
        if (publicKey instanceof EdECPublicKey edKey) {
            requireKeyTypeMatches(algorithm, KTY_OKP);
            String curve = edKey.getParams().getName();
            if (!CRV_ED25519.equals(curve)) {
                throw new IllegalArgumentException(
                        "DPoP OKP proof key must use curve Ed25519, but the key uses " + curve);
            }
            return Map.of(
                    "kty", KTY_OKP,
                    "crv", CRV_ED25519,
                    "x", encodeEd25519Point(edKey.getPoint()));
        }
        throw new IllegalArgumentException(
                "DPoP proof key must be an RSA, EC P-256 or OKP Ed25519 key pair, but was "
                        + publicKey.getAlgorithm());
    }

    /**
     * Resolves curve P-256's domain parameters from the JCA provider.
     *
     * @return the {@code secp256r1} domain parameters
     * @throws IllegalStateException if the provider does not offer curve P-256
     */
    private static ECParameterSpec resolveP256Params() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance(KTY_EC);
            parameters.init(new ECGenParameterSpec(CURVE_SECP256R1));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("JCA provider does not offer curve P-256 (secp256r1)", e);
        }
    }

    /**
     * Fails fast when an EC proof key is not on curve P-256. The comparison covers the full domain
     * parameters — curve, generator, order and cofactor — because matching only the field size would
     * accept a different 256-bit curve and publish it as {@code "crv":"P-256"}.
     * <p>
     * {@link ECParameterSpec} does not define {@code equals}, so its components are compared
     * individually; {@link java.security.spec.EllipticCurve} and {@link java.security.spec.ECPoint}
     * do define value equality.
     *
     * @param params the supplied proof key's domain parameters
     * @throws IllegalArgumentException if the parameters are not curve P-256's
     */
    private static void requireP256Curve(ECParameterSpec params) {
        boolean onP256 = P256_PARAMS.getCurve().equals(params.getCurve())
                && P256_PARAMS.getGenerator().equals(params.getGenerator())
                && P256_PARAMS.getOrder().equals(params.getOrder())
                && P256_PARAMS.getCofactor() == params.getCofactor();
        if (!onP256) {
            throw new IllegalArgumentException(
                    ("DPoP EC proof key must use curve P-256 (secp256r1), but the key's domain parameters "
                            + "are those of another curve over a %d-bit field").formatted(
                            params.getCurve().getField().getFieldSize()));
        }
    }

    /**
     * Fails fast when the requested signing algorithm does not match the proof key's type — for
     * example {@code ES256} with an RSA pair, or {@code RS256} with an EC pair.
     *
     * @param algorithm     the requested JWT signing algorithm
     * @param actualKeyType the {@code kty} of the supplied proof key
     * @throws IllegalArgumentException if the algorithm requires a different key type
     */
    private static void requireKeyTypeMatches(String algorithm, String actualKeyType) {
        String requiredKeyType = ALGORITHM_KEY_TYPES.get(algorithm);
        if (!actualKeyType.equals(requiredKeyType)) {
            throw new IllegalArgumentException(
                    "DPoP signing algorithm %s requires a %s proof key, but the key pair is %s".formatted(
                            algorithm, requiredKeyType, actualKeyType));
        }
    }

    /**
     * Builds a fresh, single-use DPoP proof for a token-endpoint request (no {@code ath}, no
     * {@code nonce}).
     *
     * @param htm the request HTTP method (e.g. {@code POST}); must not be {@code null} or blank
     * @param htu the request URI (e.g. the token endpoint); must not be {@code null} or blank
     * @return the compact-serialized, signed DPoP proof JWT
     * @throws IllegalStateException if the {@code jti} source repeats a previously issued identifier
     *         (a proof with a reused {@code jti} would be replayable and is refused)
     */
    public String generateProof(String htm, String htu) {
        return generateProof(htm, htu, null, null);
    }

    /**
     * Builds a fresh, single-use DPoP proof, optionally carrying a server-supplied {@code nonce}
     * (RFC 9449 §8) and an access-token hash {@code ath} for a protected-resource proof
     * (RFC 9449 §4.3).
     * <p>
     * The {@code htu} is normalized per RFC 9449 §4.2 — its query and fragment components are stripped
     * so the proof binds only the scheme, authority and path of the target URI.
     *
     * @param htm         the request HTTP method (e.g. {@code POST}); must not be {@code null} or blank
     * @param htu         the request URI; must not be {@code null} or blank. Query/fragment are stripped
     * @param nonce       the server-provided DPoP nonce to echo, or {@code null} when none was challenged
     * @param accessToken the access token whose {@code ath} hash binds a protected-resource proof, or
     *                    {@code null} for a token-endpoint proof (which carries no {@code ath})
     * @return the compact-serialized, signed DPoP proof JWT
     * @throws IllegalStateException if the {@code jti} source repeats a previously issued identifier
     *         (a proof with a reused {@code jti} would be replayable and is refused)
     */
    public String generateProof(String htm, String htu, @Nullable String nonce, @Nullable String accessToken) {
        Objects.requireNonNull(htm, "htm must not be null");
        Objects.requireNonNull(htu, "htu must not be null");
        if (htm.isBlank() || htu.isBlank()) {
            throw new IllegalArgumentException("htm and htu must not be blank");
        }
        String jti = jtiSource.get();
        if (issuedJtis.put(jti, Boolean.TRUE) != null) {
            LOGGER.warn(ClientLogMessages.WARN.DPOP_JTI_REUSE);
            throw new IllegalStateException(
                    "DPoP proof 'jti' reuse detected; refusing to emit a replayable proof");
        }
        long now = Instant.now().getEpochSecond();
        String header = "{\"typ\":\"" + DPOP_TYP + "\",\"alg\":\"" + jwtAlgorithm + "\",\"jwk\":" + jwkJson + "}";
        // htu is the request URI, sourced from the AS's own discovery metadata; strip its query and
        // fragment (RFC 9449 §4.2) then escape every JSON control character per RFC 8259.
        StringBuilder payload = new StringBuilder("{\"jti\":\"").append(JsonEscaper.escape(jti))
                .append("\",\"htm\":\"").append(JsonEscaper.escape(htm))
                .append("\",\"htu\":\"").append(JsonEscaper.escape(normalizeHtu(htu)))
                .append("\",\"iat\":").append(now);
        if (accessToken != null) {
            payload.append(",\"ath\":\"").append(JsonEscaper.escape(computeAth(accessToken))).append('"');
        }
        if (nonce != null) {
            payload.append(",\"nonce\":\"").append(JsonEscaper.escape(nonce)).append('"');
        }
        payload.append('}');
        String signingInput = encode(header) + "." + encode(payload.toString());
        return signingInput + "." + sign(signingInput);
    }

    /**
     * Strips the query and fragment from a request URI so the {@code htu} claim binds only the
     * scheme, authority and path (RFC 9449 §4.2).
     */
    private static String normalizeHtu(String htu) {
        int cut = htu.length();
        int query = htu.indexOf('?');
        if (query >= 0) {
            cut = query;
        }
        int fragment = htu.indexOf('#');
        if (fragment >= 0 && fragment < cut) {
            cut = fragment;
        }
        return htu.substring(0, cut);
    }

    /**
     * Computes the RFC 9449 §4.3 {@code ath} claim — the base64url-encoded SHA-256 hash of the ASCII
     * encoding of the access-token value — binding a protected-resource proof to the token it presents.
     */
    private static String computeAth(String accessToken) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(accessToken.getBytes(StandardCharsets.US_ASCII));
            return BASE64_URL.encodeToString(hash);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 not available for DPoP ath claim", e);
        }
    }

    /**
     * @return the RFC 7638 base64url JWK thumbprint of the proof key — the {@code cnf.jkt} value the
     *         issued access token is bound to
     */
    public String jkt() {
        return jkt;
    }

    private String sign(String signingInput) {
        try {
            Signature signature = Signature.getInstance(jcaAlgorithm);
            if (ALG_PS256.equals(jwtAlgorithm)) {
                // The JCA RSASSA-PSS instance carries no defaults — PS256's parameters are explicit.
                signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            }
            signature.initSign(keyPair.getPrivate());
            signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
            byte[] rawSignature = signature.sign();
            if (ALG_ES256.equals(jwtAlgorithm)) {
                // SHA256withECDSA emits ASN.1/DER; JOSE requires the IEEE P1363 R||S concatenation.
                rawSignature = EcdsaSignatureFormatConverter.toJoseSignature(rawSignature, ALG_ES256);
            }
            return BASE64_URL.encodeToString(rawSignature);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to sign DPoP proof", e);
        }
    }

    /**
     * Encodes an RSA JWK member as an unsigned big-endian base64url value, stripping the sign byte
     * {@link BigInteger#toByteArray()} prepends. Suitable for {@code e} and {@code n}, which are
     * variable-width; it MUST NOT be used for EC coordinates, which are fixed-width and require
     * left-padding — see {@link #base64UrlFixedWidth(BigInteger, int)}.
     */
    private static String base64UrlUnsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return BASE64_URL.encodeToString(bytes);
    }

    /**
     * Encodes a fixed-width JWK member as a big-endian base64url value left-padded with zeros to
     * exactly {@code width} bytes, per RFC 7518 §6.2.1.2.
     *
     * @param value the non-negative value to encode
     * @param width the fixed member width in bytes
     * @return the base64url encoding of the zero-padded big-endian value
     * @throws IllegalArgumentException if the value does not fit into {@code width} bytes
     */
    private static String base64UrlFixedWidth(BigInteger value, int width) {
        return BASE64_URL.encodeToString(toFixedWidth(value, width));
    }

    /**
     * Renders a non-negative value as a big-endian byte array of exactly {@code width} bytes.
     *
     * @param value the non-negative value to render
     * @param width the target width in bytes
     * @return the zero-padded big-endian representation
     * @throws IllegalArgumentException if the value does not fit into {@code width} bytes
     */
    private static byte[] toFixedWidth(BigInteger value, int width) {
        byte[] magnitude = value.toByteArray();
        int offset = 0;
        while (offset < magnitude.length - 1 && magnitude[offset] == 0) {
            offset++;
        }
        int significantLength = magnitude.length - offset;
        if (significantLength > width) {
            throw new IllegalArgumentException(
                    "JWK member is %d bytes, exceeds the %d-byte member width".formatted(significantLength, width));
        }
        byte[] fixedWidth = new byte[width];
        System.arraycopy(magnitude, offset, fixedWidth, width - significantLength, significantLength);
        return fixedWidth;
    }

    /**
     * Encodes an Ed25519 public point as the RFC 8032 32-byte {@code x} member: the point's
     * {@code y} coordinate big-endian left-padded to 32 bytes, byte-reversed to little-endian, with
     * the most significant bit of the final byte set when {@code x} is odd.
     * <p>
     * This is the exact inverse of {@code JwkKeyHandler.parseOkpKey}, the reference implementation
     * for the encoding.
     */
    private static String encodeEd25519Point(EdECPoint point) {
        byte[] encoded = toFixedWidth(point.getY(), ED25519_KEY_BYTES);
        reverseInPlace(encoded);
        if (point.isXOdd()) {
            encoded[encoded.length - 1] |= (byte) 0x80;
        }
        return BASE64_URL.encodeToString(encoded);
    }

    /**
     * Reverses a byte array in place (big-endian to little-endian conversion).
     */
    private static void reverseInPlace(byte[] array) {
        for (int i = 0, j = array.length - 1; i < j; i++, j--) {
            byte tmp = array[i];
            array[i] = array[j];
            array[j] = tmp;
        }
    }

    private static String encode(String json) {
        return BASE64_URL.encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static String toJcaAlgorithm(String jwtAlgorithm) {
        return switch (jwtAlgorithm) {
            case "RS256" -> "SHA256withRSA";
            case "RS384" -> "SHA384withRSA";
            case "RS512" -> "SHA512withRSA";
            case ALG_PS256 -> "RSASSA-PSS";
            case ALG_ES256 -> "SHA256withECDSA";
            // The JCA signature algorithm name for EdDSA over curve Ed25519 is the curve name itself,
            // so the JWK 'crv' constant is the single definition of that string.
            case "EdDSA" -> CRV_ED25519;
            default -> throw new IllegalArgumentException("unsupported DPoP signing algorithm: " + jwtAlgorithm);
        };
    }
}
