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
package de.cuioss.sheriff.token.client.internal;

import org.jspecify.annotations.Nullable;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

/**
 * A {@link HttpResponse.BodyHandler} that streams a response body into a {@link String} while
 * enforcing a hard byte ceiling <em>during</em> the read, rather than buffering the whole body and
 * checking its size afterwards.
 * <p>
 * The default {@link HttpResponse.BodyHandlers#ofString()} fully materializes the response body in
 * memory before the caller can inspect its length, so a size cap applied to the returned string
 * defends nothing against a hostile or misbehaving authorization server (M7): the out-of-memory has
 * already happened. This handler subscribes to the response body as a stream of {@link ByteBuffer}s,
 * accumulates them into a bounded buffer, and completes the body exceptionally with an
 * {@link IOException} the instant the running total would exceed {@code maxBytes} — cancelling the
 * subscription so no further bytes are read. Back-channel clients translate that {@link IOException}
 * into the declared {@code TransportException} on their normal {@code IOException} catch path.
 * <p>
 * The rejection message names the ceiling <em>and</em> its origin: callers supply a
 * {@code boundOrigin} descriptor identifying the knob that set the ceiling and whether it is
 * settable, so a reader of the failure can tell a tunable bound from a fixed one.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
public final class BoundedContentBodyHandler implements HttpResponse.BodyHandler<String> {

    private final int maxBytes;
    private final Charset charset;
    private final String boundOrigin;

    private BoundedContentBodyHandler(int maxBytes, Charset charset, String boundOrigin) {
        if (maxBytes < 0) {
            throw new IllegalArgumentException("maxBytes must not be negative");
        }
        this.maxBytes = maxBytes;
        this.charset = Objects.requireNonNull(charset, "charset must not be null");
        this.boundOrigin = Objects.requireNonNull(boundOrigin, "boundOrigin must not be null");
    }

    /**
     * @param maxBytes    the maximum number of body bytes to read before failing; must not be negative
     * @param boundOrigin the human-readable provenance of the ceiling — the knob that set it, and
     *                    whether it is settable; reported verbatim in the rejection message
     * @return a UTF-8 bounded body handler capped at {@code maxBytes}
     */
    public static BoundedContentBodyHandler of(int maxBytes, String boundOrigin) {
        return new BoundedContentBodyHandler(maxBytes, StandardCharsets.UTF_8, boundOrigin);
    }

    @Override
    public HttpResponse.BodySubscriber<String> apply(HttpResponse.ResponseInfo responseInfo) {
        return new BoundedStringSubscriber(maxBytes, charset, boundOrigin);
    }

    /**
     * Accumulates the streamed body up to {@code maxBytes}, failing fast when the running total would
     * exceed the ceiling.
     */
    private static final class BoundedStringSubscriber implements HttpResponse.BodySubscriber<String> {

        private final int maxBytes;
        private final Charset charset;
        private final String boundOrigin;
        private final CompletableFuture<String> result = new CompletableFuture<>();
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private Flow.@Nullable Subscription subscription;
        private long total;

        BoundedStringSubscriber(int maxBytes, Charset charset, String boundOrigin) {
            this.maxBytes = maxBytes;
            this.charset = charset;
            this.boundOrigin = boundOrigin;
        }

        @Override
        public CompletionStage<String> getBody() {
            return result;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            for (ByteBuffer item : items) {
                int remaining = item.remaining();
                total += remaining;
                if (total > maxBytes) {
                    if (subscription != null) {
                        subscription.cancel();
                    }
                    buffer.reset();
                    result.completeExceptionally(new IOException(
                            "response body exceeds the maximum allowed size of " + maxBytes + " bytes ("
                                    + boundOrigin + ")"));
                    return;
                }
                byte[] chunk = new byte[remaining];
                item.get(chunk);
                buffer.writeBytes(chunk);
            }
        }

        @Override
        public void onError(Throwable throwable) {
            result.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            if (!result.isDone()) {
                result.complete(buffer.toString(charset));
            }
        }
    }
}
