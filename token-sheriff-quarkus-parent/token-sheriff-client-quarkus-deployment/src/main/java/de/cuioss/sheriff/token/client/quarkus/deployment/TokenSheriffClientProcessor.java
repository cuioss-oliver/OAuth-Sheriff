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
package de.cuioss.sheriff.token.client.quarkus.deployment;

import de.cuioss.sheriff.token.client.quarkus.TokenSheriffClientProducer;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.logging.LogRecord;
import de.cuioss.tools.logging.LogRecordModel;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;

/**
 * Build-time processor for the Token-Sheriff client Quarkus extension.
 * <p>
 * At augmentation it registers the {@code token-sheriff-client} feature and contributes the
 * {@link TokenSheriffClientProducer} to the CDI bean archive so the framework-agnostic client engine
 * is exposed as {@link jakarta.enterprise.context.ApplicationScoped} beans. The extension runtime jar
 * is not part of the application's bean-discovery archive by default, so the producer is registered
 * explicitly here ({@code CLIENT-21}).
 */
public class TokenSheriffClientProcessor {

    /**
     * The feature name for the Token-Sheriff client extension.
     */
    private static final String FEATURE = "token-sheriff-client";

    /**
     * Logger for build-time processing.
     */
    private static final CuiLogger LOGGER = new CuiLogger(TokenSheriffClientProcessor.class);

    /**
     * LogRecord for feature registration.
     */
    private static final LogRecord TOKEN_SHERIFF_CLIENT_FEATURE_REGISTERED = LogRecordModel.builder()
            .template("Token-Sheriff client feature registered")
            .prefix("TokenSheriffClient_Q_D")
            .identifier(1)
            .build();

    /**
     * Register the Token-Sheriff client feature.
     *
     * @return a {@link FeatureBuildItem} for the {@code token-sheriff-client} feature
     */
    @BuildStep
    public FeatureBuildItem feature() {
        LOGGER.info(TOKEN_SHERIFF_CLIENT_FEATURE_REGISTERED);
        return new FeatureBuildItem(FEATURE);
    }

    /**
     * Register the client engine's CDI producer as an additional bean. The extension's runtime jar is
     * not part of the application's bean-discovery archive, so the {@link TokenSheriffClientProducer}
     * — and the engine beans it produces — must be contributed explicitly during augmentation.
     *
     * @return the {@link AdditionalBeanBuildItem} carrying the producer bean class
     */
    @BuildStep
    public AdditionalBeanBuildItem additionalBeans() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClass(TokenSheriffClientProducer.class)
                .build();
    }
}
