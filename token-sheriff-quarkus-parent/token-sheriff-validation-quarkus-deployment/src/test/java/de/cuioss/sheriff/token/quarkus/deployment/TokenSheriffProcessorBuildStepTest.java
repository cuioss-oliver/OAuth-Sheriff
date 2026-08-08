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
package de.cuioss.sheriff.token.quarkus.deployment;

import de.cuioss.sheriff.token.quarkus.mapper.DiscoverableClaimMapper;
import de.cuioss.sheriff.token.quarkus.producer.JsonWebTokenAdapter;
import de.cuioss.sheriff.token.validation.TokenValidator;
import de.cuioss.sheriff.token.validation.domain.token.AccessTokenContent;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.micrometer.core.instrument.MeterRegistry;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.UnremovableBeanBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.devui.spi.JsonRPCProvidersBuildItem;
import io.quarkus.devui.spi.page.CardPageBuildItem;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link TokenSheriffProcessor} build step methods.
 */
@EnableTestLogger
@DisplayName("Tests for TokenSheriffProcessor build steps")
class TokenSheriffProcessorBuildStepTest {

    private final TokenSheriffProcessor processor = new TokenSheriffProcessor();

    @Test
    @DisplayName("Should create the feature build item")
    void shouldCreateFeatureBuildItem() {
        FeatureBuildItem featureItem = processor.feature();

        assertNotNull(featureItem);
        assertEquals("token-sheriff", featureItem.getName());
    }

    @Test
    @DisplayName("Should register Quarkus-specific types for reflection and no core types")
    void shouldRegisterQuarkusSpecificClassesForReflection() {
        List<ReflectiveClassBuildItem> reflectiveItems = new ArrayList<>();
        BuildProducer<ReflectiveClassBuildItem> producer = reflectiveItems::add;

        processor.registerQuarkusSpecificClassesForReflection(producer);

        Set<String> registered = new HashSet<>();
        for (ReflectiveClassBuildItem item : reflectiveItems) {
            registered.addAll(item.getClassNames());
        }
        assertAll("Quarkus-specific reflection registrations",
                () -> assertTrue(registered.contains(MeterRegistry.class.getName()),
                        "MeterRegistry should stay registered by the extension"),
                () -> assertTrue(registered.contains(JsonWebToken.class.getName()),
                        "JsonWebToken should stay registered by the extension"),
                () -> assertTrue(registered.contains(JsonWebTokenAdapter.class.getName()),
                        "JsonWebTokenAdapter should stay registered by the extension"),
                () -> assertTrue(registered.contains(DiscoverableClaimMapper.class.getName()),
                        "DiscoverableClaimMapper should stay registered by the extension"),
                () -> assertFalse(registered.contains(TokenValidator.class.getName()),
                        "Core types ship their own metadata and must not creep back into the extension"),
                () -> assertFalse(registered.contains(AccessTokenContent.class.getName()),
                        "Core types ship their own metadata and must not creep back into the extension"));
    }

    @Test
    @DisplayName("Should create the additional beans build item")
    void shouldCreateAdditionalBeans() {
        AdditionalBeanBuildItem beanItem = processor.additionalBeans();

        assertNotNull(beanItem);
    }

    @Test
    @DisplayName("Should create the DevUI card with both pages")
    void shouldCreateDevUICard() {
        CardPageBuildItem cardItem = processor.createJwtDevUICard();

        assertNotNull(cardItem);
        assertFalse(cardItem.getPages().isEmpty());
        assertEquals(2, cardItem.getPages().size());
    }

    @Test
    @DisplayName("Should create the DevUI JSON-RPC service")
    void shouldCreateDevUIJsonRPCService() {
        JsonRPCProvidersBuildItem jsonRpcItem = processor.createJwtDevUIJsonRPCService();

        assertNotNull(jsonRpcItem);
    }

    @Test
    @DisplayName("Should register unremovable beans")
    void shouldRegisterUnremovableBeans() {
        List<UnremovableBeanBuildItem> unremovableBeans = new ArrayList<>();
        BuildProducer<UnremovableBeanBuildItem> producer = unremovableBeans::add;

        processor.registerUnremovableBeans(producer);

        assertEquals(1, unremovableBeans.size());
    }
}
