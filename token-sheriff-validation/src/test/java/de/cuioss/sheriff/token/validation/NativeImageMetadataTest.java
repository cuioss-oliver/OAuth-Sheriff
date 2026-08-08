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
package de.cuioss.sheriff.token.validation;

import jakarta.json.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Drift guard for the GraalVM native-image metadata this module ships.
 * <p>
 * The core library declares its own reflection contract under
 * {@code META-INF/native-image/de.cuioss.sheriff.token/token-sheriff-validation/}, where GraalVM
 * auto-detects it from the packaged jar. Because that contract is a hand-maintained list of class
 * names, it can silently rot when a listed type is renamed, moved or deleted. This test resolves
 * every listed name against the module's own classpath so such a drift fails the build here rather
 * than at native-image build time in a downstream consumer.
 *
 * @author Oliver Wolff
 */
@DisplayName("Tests for the shipped native-image metadata")
class NativeImageMetadataTest {

    private static final String METADATA_DIR =
            "META-INF/native-image/de.cuioss.sheriff.token/token-sheriff-validation/";
    private static final String REFLECT_CONFIG = METADATA_DIR + "reflect-config.json";
    private static final String NATIVE_IMAGE_PROPERTIES = METADATA_DIR + "native-image.properties";
    private static final String CORE_PACKAGE_PREFIX = "de.cuioss.sheriff.token.";
    private static final String RUNTIME_INITIALIZED_CLASS =
            "de.cuioss.sheriff.token.validation.jwks.http.HttpJwksLoader";
    private static final String NAME_ATTRIBUTE = "name";

    @Nested
    @DisplayName("reflect-config.json")
    class ReflectConfig {

        @Test
        @DisplayName("Should parse as a JSON array of objects each carrying a name")
        void shouldParseAsArrayOfObjectsEachCarryingAName() {
            JsonArray entries = readReflectConfig();

            assertFalse(entries.isEmpty(), "reflect-config.json should declare at least one entry");
            List<Executable> assertions = new ArrayList<>(entries.size());
            for (JsonValue entry : entries) {
                assertions.add(() -> {
                    assertEquals(JsonValue.ValueType.OBJECT, entry.getValueType(),
                            "Entry should be a JSON object: " + entry);
                    JsonObject object = entry.asJsonObject();
                    assertTrue(object.containsKey(NAME_ATTRIBUTE),
                            "Entry should carry a name attribute: " + object);
                    assertFalse(object.getString(NAME_ATTRIBUTE).isBlank(),
                            "Entry name should not be blank: " + object);
                });
            }
            assertAll("every entry is an object carrying a non-blank name", assertions);
        }

        @Test
        @DisplayName("Should resolve every listed name on the core module classpath")
        void shouldResolveEveryListedNameOnTheCoreClasspath() {
            List<String> names = registeredNames();

            List<Executable> assertions = new ArrayList<>(names.size());
            for (String name : names) {
                assertions.add(() -> assertDoesNotThrow(
                        () -> Class.forName(name, false, classLoader()),
                        "Registered type is not resolvable on the core classpath: " + name));
            }
            assertAll("every registered type resolves", assertions);
        }

        @Test
        @DisplayName("Should list core types only")
        void shouldListCoreTypesOnly() {
            List<String> names = registeredNames();

            List<Executable> assertions = new ArrayList<>(names.size());
            for (String name : names) {
                assertions.add(() -> assertTrue(name.startsWith(CORE_PACKAGE_PREFIX),
                        "Only core types belong in the core reflection contract: " + name));
            }
            assertAll("every registered type is core-owned", assertions);
        }
    }

    @Nested
    @DisplayName("native-image.properties")
    class NativeImageProperties {

        @Test
        @DisplayName("Should be shipped and initialize HttpJwksLoader at run time")
        void shouldBeShippedAndInitializeHttpJwksLoaderAtRunTime() {
            String properties = readResource(NATIVE_IMAGE_PROPERTIES);

            assertAll("runtime initialization contract",
                    () -> assertTrue(properties.contains("--initialize-at-run-time"),
                            "native-image.properties should declare --initialize-at-run-time"),
                    () -> assertTrue(properties.contains(RUNTIME_INITIALIZED_CLASS),
                            "native-image.properties should name " + RUNTIME_INITIALIZED_CLASS));
        }
    }

    private static List<String> registeredNames() {
        JsonArray entries = readReflectConfig();
        List<String> names = new ArrayList<>(entries.size());
        for (JsonValue entry : entries) {
            names.add(entry.asJsonObject().getString(NAME_ATTRIBUTE));
        }
        return names;
    }

    private static JsonArray readReflectConfig() {
        try (JsonReader reader = Json.createReader(new StringReader(readResource(REFLECT_CONFIG)))) {
            return reader.readArray();
        }
    }

    private static String readResource(String resource) {
        try (InputStream stream = classLoader().getResourceAsStream(resource)) {
            assertNotNull(stream, "Shipped native-image metadata is missing: " + resource);
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Unable to read " + resource, e);
        }
    }

    private static ClassLoader classLoader() {
        return NativeImageMetadataTest.class.getClassLoader();
    }
}
