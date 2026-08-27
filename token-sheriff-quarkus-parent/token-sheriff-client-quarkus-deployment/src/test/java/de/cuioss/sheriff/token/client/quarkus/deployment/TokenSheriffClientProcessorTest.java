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
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link TokenSheriffClientProcessor}.
 */
@EnableTestLogger
class TokenSheriffClientProcessorTest {

    private final TokenSheriffClientProcessor processor = new TokenSheriffClientProcessor();

    @Test
    @DisplayName("Should register the token-sheriff-client feature")
    void shouldRegisterTokenSheriffClientFeature() {
        FeatureBuildItem featureItem = processor.feature();

        assertNotNull(featureItem, "the feature build item must be produced");
        assertEquals("token-sheriff-client", featureItem.getName(), "the feature name must be stable");
    }

    @Test
    @DisplayName("Should contribute the client producer to the CDI bean archive")
    void shouldRegisterClientProducerBean() {
        AdditionalBeanBuildItem beanItem = processor.additionalBeans();

        assertNotNull(beanItem, "the additional-bean build item must be produced");
        assertTrue(beanItem.getBeanClasses().contains(TokenSheriffClientProducer.class.getName()),
                "the producer bean class must be registered so the engine beans are discoverable");
    }
}
