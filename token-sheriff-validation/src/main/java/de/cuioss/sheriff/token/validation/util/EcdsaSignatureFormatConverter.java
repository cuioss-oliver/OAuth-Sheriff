/*
 * Copyright © 2022 CUI-OpenSource-Software (info@cuioss.de)
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
package de.cuioss.sheriff.token.validation.util;

import de.cuioss.tools.logging.CuiLogger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SignatureException;

/**
 * Utility class for converting ECDSA signatures between IEEE P1363 and ASN.1/DER formats.
 *
 * <p>This class addresses the incompatibility between JWT standard ECDSA signatures
 * (IEEE P1363 format - raw R,S concatenation) and JDK ECDSA verification
 * (ASN.1/DER format - structured encoding).</p>
 *
 * <h3>Format Details:</h3>
 * <ul>
 *   <li><strong>IEEE P1363:</strong> Raw concatenation of R and S components (R || S)</li>
 *   <li><strong>ASN.1/DER:</strong> Structured encoding: SEQUENCE { r INTEGER, s INTEGER }</li>
 * </ul>
 *
 * <h3>Algorithm Support:</h3>
 * <ul>
 *   <li><strong>ES256 (P-256):</strong> 32-byte R and S components (64 bytes total in P1363)</li>
 *   <li><strong>ES384 (P-384):</strong> 48-byte R and S components (96 bytes total in P1363)</li>
 *   <li><strong>ES512 (P-521):</strong> 66-byte R and S components (132 bytes total in P1363)</li>
 * </ul>
 * @since 1.0
 */
public class EcdsaSignatureFormatConverter {

    private static final CuiLogger LOGGER = new CuiLogger(EcdsaSignatureFormatConverter.class);

    /** ASN.1 tag identifying a DER SEQUENCE. */
    private static final int ASN1_SEQUENCE_TAG = 0x30;

    /** ASN.1 tag identifying a DER INTEGER. */
    private static final int ASN1_INTEGER_TAG = 0x02;

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private EcdsaSignatureFormatConverter() {
        // Utility class
    }

    /**
     * Converts an ECDSA signature from IEEE P1363 format to ASN.1/DER format.
     *
     * <p>This conversion is necessary when validating JWT tokens with ECDSA signatures
     * using the JDK's ECDSA signature verification, which expects ASN.1/DER format.</p>
     *
     * @param ieeeP1363Signature the signature in IEEE P1363 format (raw R||S concatenation)
     * @param algorithm the ECDSA algorithm (ES256, ES384, or ES512)
     * @return the signature in ASN.1/DER format
     * @throws SignatureException if the conversion fails or the signature format is invalid
     */
    @SuppressWarnings("java:S125")
    public static byte[] toJCACompatibleSignature(byte[] ieeeP1363Signature, String algorithm) throws SignatureException {
        if (ieeeP1363Signature == null) {
            throw new SignatureException("Signature cannot be null");
        }

        // Determine expected signature length and component size based on algorithm
        int componentSize = getComponentSize(algorithm);
        int expectedLength = componentSize * 2;

        if (ieeeP1363Signature.length != expectedLength) {
            throw new SignatureException("Invalid %s signature length: expected %s bytes, got %s bytes".formatted(
                    algorithm, expectedLength, ieeeP1363Signature.length));
        }

        try {
            // Extract R and S components
            byte[] rBytes = new byte[componentSize];
            byte[] sBytes = new byte[componentSize];

            System.arraycopy(ieeeP1363Signature, 0, rBytes, 0, componentSize);
            System.arraycopy(ieeeP1363Signature, componentSize, sBytes, 0, componentSize);

            // Convert to BigInteger (handles leading zeros correctly)
            BigInteger r = new BigInteger(1, rBytes); // Positive BigInteger
            BigInteger s = new BigInteger(1, sBytes); // Positive BigInteger

            // Encode as ASN.1/DER SEQUENCE { r INTEGER, s INTEGER }
            return encodeAsn1Signature(r, s);

        } catch (IOException e) {
            throw new SignatureException("Failed to convert IEEE P1363 signature to ASN.1/DER format: " + e.getMessage(), e);
        }
    }

    /**
     * Converts an ECDSA signature from ASN.1/DER format to IEEE P1363 format.
     *
     * <p>This is the symmetric outbound counterpart to
     * {@link #toJCACompatibleSignature(byte[], String)}: the JCA {@code SHA*withECDSA} signer emits
     * an ASN.1/DER {@code SEQUENCE { r INTEGER, s INTEGER }}, whereas JOSE requires the fixed-width
     * IEEE P1363 {@code R || S} concatenation. Use it when producing a JWS/JWT signature.</p>
     *
     * <p>Two DER encoding traps are handled explicitly:</p>
     * <ul>
     *   <li>A DER INTEGER carries a leading {@code 0x00} pad byte when the high bit of the first
     *       significant byte is set — the pad is stripped.</li>
     *   <li>A DER INTEGER drops leading zero bytes — each component is left-padded back to the
     *       algorithm's fixed component width.</li>
     * </ul>
     *
     * @param derSignature the signature in ASN.1/DER format as emitted by the JCA ECDSA signer
     * @param algorithm the ECDSA algorithm (ES256, ES384, or ES512)
     * @return the signature in IEEE P1363 format (raw R||S concatenation)
     * @throws SignatureException if the signature is null, the algorithm is unsupported, or the DER
     *         encoding is malformed (wrong tag, truncated length, trailing bytes, or a component
     *         longer than the algorithm's component width)
     * @since 1.0
     */
    public static byte[] toJoseSignature(byte[] derSignature, String algorithm) throws SignatureException {
        if (derSignature == null) {
            throw new SignatureException("Signature cannot be null");
        }

        int componentSize = getComponentSize(algorithm);

        var reader = new DerReader(derSignature);
        int sequenceLength = reader.readTagAndLength(ASN1_SEQUENCE_TAG, "SEQUENCE");
        if (sequenceLength != reader.remaining()) {
            throw new SignatureException(
                    "Invalid DER signature: SEQUENCE declares %s content bytes but %s remain".formatted(
                            sequenceLength, reader.remaining()));
        }

        byte[] rComponent = readFixedWidthComponent(reader, componentSize, "R");
        byte[] sComponent = readFixedWidthComponent(reader, componentSize, "S");

        if (reader.remaining() != 0) {
            throw new SignatureException("Invalid DER signature: %s trailing byte(s) after the S component".formatted(
                    reader.remaining()));
        }

        byte[] joseSignature = new byte[componentSize * 2];
        System.arraycopy(rComponent, 0, joseSignature, 0, componentSize);
        System.arraycopy(sComponent, 0, joseSignature, componentSize, componentSize);

        LOGGER.debug("Converted ASN.1/DER signature to IEEE P1363 format (length: %s bytes)", joseSignature.length);

        return joseSignature;
    }

    /**
     * Reads one DER INTEGER and normalizes it to the algorithm's fixed component width.
     *
     * @param reader the cursor positioned at the INTEGER tag
     * @param componentSize the fixed component width in bytes
     * @param componentName the component name used in error messages (R or S)
     * @return the component left-padded with zeros to exactly {@code componentSize} bytes
     * @throws SignatureException if the INTEGER is malformed or exceeds {@code componentSize}
     */
    private static byte[] readFixedWidthComponent(DerReader reader, int componentSize, String componentName)
            throws SignatureException {
        int length = reader.readTagAndLength(ASN1_INTEGER_TAG, "INTEGER");
        byte[] rawValue = reader.readBytes(length);

        if (rawValue.length == 0) {
            throw new SignatureException("Invalid DER signature: %s component has zero length".formatted(componentName));
        }

        // Strip leading zero padding (DER adds 0x00 when the high bit is set) while keeping at least one byte
        int offset = 0;
        while (offset < rawValue.length - 1 && rawValue[offset] == 0) {
            offset++;
        }
        int significantLength = rawValue.length - offset;

        if (significantLength > componentSize) {
            throw new SignatureException(
                    "Invalid DER signature: %s component is %s bytes, exceeds the %s-byte component width".formatted(
                            componentName, significantLength, componentSize));
        }

        // Left-pad back to the fixed width (DER drops leading zero bytes)
        byte[] component = new byte[componentSize];
        System.arraycopy(rawValue, offset, component, componentSize - significantLength, significantLength);
        return component;
    }

    /**
     * Gets the component size in bytes for the specified ECDSA algorithm.
     *
     * @param algorithm the ECDSA algorithm (ES256, ES384, or ES512)
     * @return the component size in bytes
     * @throws SignatureException if the algorithm is not supported
     */
    private static int getComponentSize(String algorithm) throws SignatureException {
        return switch (algorithm.toUpperCase()) {
            case "ES256" -> 32; // P-256: 256 bits / 8 = 32 bytes
            case "ES384" -> 48; // P-384: 384 bits / 8 = 48 bytes
            case "ES512" -> 66; // P-521: 521 bits / 8 = 65.125 -> 66 bytes (rounded up)
            default -> throw new SignatureException("Unsupported ECDSA algorithm: " + algorithm);
        };
    }

    /**
     * Encodes R and S components as ASN.1/DER SEQUENCE { r INTEGER, s INTEGER }.
     *
     * <p>ASN.1 DER encoding rules:
     * <ul>
     *   <li>SEQUENCE tag: 0x30</li>
     *   <li>Length encoding (definite form)</li>
     *   <li>INTEGER tag: 0x02</li>
     *   <li>Length of integer</li>
     *   <li>Integer value (with padding byte if MSB is 1 to ensure positive)</li>
     * </ul></p>
     *
     * @param r the R component as a BigInteger
     * @param s the S component as a BigInteger
     * @return the ASN.1/DER encoded signature
     * @throws IOException if encoding fails
     */
    private static byte[] encodeAsn1Signature(BigInteger r, BigInteger s) throws IOException {
        // Encode R component
        byte[] rEncoded = encodeAsn1Integer(r);

        // Encode S component
        byte[] sEncoded = encodeAsn1Integer(s);

        // Calculate total content length
        int contentLength = rEncoded.length + sEncoded.length;

        // Build the complete SEQUENCE
        ByteArrayOutputStream sequence = new ByteArrayOutputStream();

        // SEQUENCE tag
        sequence.write(ASN1_SEQUENCE_TAG);

        // Length of content
        writeLength(sequence, contentLength);

        // R component
        sequence.write(rEncoded);

        // S component
        sequence.write(sEncoded);

        byte[] result = sequence.toByteArray();

        LOGGER.debug("Converted IEEE P1363 signature to ASN.1/DER format (length: %s bytes)", result.length);

        return result;
    }

    /**
     * Encodes a BigInteger as ASN.1/DER INTEGER.
     *
     * @param value the BigInteger value to encode
     * @return the ASN.1/DER encoded INTEGER
     * @throws IOException if encoding fails
     */
    private static byte[] encodeAsn1Integer(BigInteger value) throws IOException {
        byte[] valueBytes = value.toByteArray(); // BigInteger.toByteArray() handles sign bit correctly

        ByteArrayOutputStream integerEncoding = new ByteArrayOutputStream();

        // INTEGER tag
        integerEncoding.write(ASN1_INTEGER_TAG);

        // Length of value
        writeLength(integerEncoding, valueBytes.length);

        // Value
        integerEncoding.write(valueBytes);

        return integerEncoding.toByteArray();
    }

    /**
     * Writes a length value in ASN.1/DER definite form.
     *
     * <p>DER length encoding:
     * <ul>
     *   <li>Short form (length &lt; 128): single byte with the length value</li>
     *   <li>Long form (length ≥ 128): first byte = 0x80 | number_of_length_bytes, followed by length bytes</li>
     * </ul></p>
     *
     * @param out the output stream to write to
     * @param length the length value to encode
     */
    private static void writeLength(ByteArrayOutputStream out, int length) {
        if (length < 128) {
            // Short form
            out.write(length);
        } else {
            // Long form - determine how many bytes needed
            int bytesNeeded = 0;
            int temp = length;
            while (temp > 0) {
                bytesNeeded++;
                temp >>= 8;
            }

            // Write first byte: 0x80 | number of length bytes
            out.write(0x80 | bytesNeeded);

            // Write length bytes (most significant first)
            for (int i = bytesNeeded - 1; i >= 0; i--) {
                out.write((length >> (i * 8)) & 0xFF);
            }
        }
    }

    /**
     * Minimal forward-only cursor over a DER byte array.
     *
     * <p>Reads only the tag/length/value shapes an ECDSA signature can contain and fails with
     * {@link SignatureException} on any truncation or unsupported encoding, so a malformed input can
     * never be read past the end of the buffer.</p>
     */
    private static final class DerReader {

        /** Maximum number of long-form length bytes accepted; bounds the decoded length well below overflow. */
        private static final int MAX_LONG_FORM_LENGTH_BYTES = 3;

        private final byte[] data;
        private int position;

        DerReader(byte[] data) {
            this.data = data;
        }

        /**
         * @return the number of unread bytes
         */
        int remaining() {
            return data.length - position;
        }

        /**
         * Reads an expected tag byte followed by its length.
         *
         * @param expectedTag the ASN.1 tag that must appear at the cursor
         * @param description the element name used in error messages
         * @return the decoded content length
         * @throws SignatureException if the tag does not match or the encoding is truncated
         */
        int readTagAndLength(int expectedTag, String description) throws SignatureException {
            int tag = readByte(description + " tag");
            if (tag != expectedTag) {
                throw new SignatureException("Invalid DER signature: expected %s tag 0x%02X, got 0x%02X".formatted(
                        description, expectedTag, tag));
            }
            return readLength(description);
        }

        /**
         * Reads a definite-form length in either short or long form.
         *
         * @param description the element name used in error messages
         * @return the decoded content length
         * @throws SignatureException if the length is truncated or uses an unsupported encoding
         */
        private int readLength(String description) throws SignatureException {
            int firstByte = readByte(description + " length");
            if (firstByte < 0x80) {
                return firstByte;
            }
            int lengthByteCount = firstByte & 0x7F;
            if (lengthByteCount == 0 || lengthByteCount > MAX_LONG_FORM_LENGTH_BYTES) {
                throw new SignatureException("Invalid DER signature: unsupported %s length encoding 0x%02X".formatted(
                        description, firstByte));
            }
            int length = 0;
            for (int i = 0; i < lengthByteCount; i++) {
                length = (length << 8) | readByte(description + " length");
            }
            return length;
        }

        /**
         * Reads a single unsigned byte.
         *
         * @param elementName the element name used in the truncation message
         * @return the byte value in the range 0-255
         * @throws SignatureException if the cursor is already at the end of the buffer
         */
        private int readByte(String elementName) throws SignatureException {
            if (position >= data.length) {
                throw new SignatureException("Invalid DER signature: truncated while reading " + elementName);
            }
            return data[position++] & 0xFF;
        }

        /**
         * Reads a fixed number of bytes.
         *
         * @param length the number of bytes to read
         * @return the bytes read
         * @throws SignatureException if fewer than {@code length} bytes remain
         */
        byte[] readBytes(int length) throws SignatureException {
            if (length > remaining()) {
                throw new SignatureException("Invalid DER signature: truncated, need %s byte(s) but %s remain".formatted(
                        length, remaining()));
            }
            byte[] value = new byte[length];
            System.arraycopy(data, position, value, 0, length);
            position += length;
            return value;
        }
    }
}