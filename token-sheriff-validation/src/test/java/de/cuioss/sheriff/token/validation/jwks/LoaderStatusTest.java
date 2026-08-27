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
package de.cuioss.sheriff.token.validation.jwks;

import de.cuioss.sheriff.token.commons.transport.LoaderStatus;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit test for {@link LoaderStatus} enum.
 *
 * @author Oliver Wolff
 */
@EnableGeneratorController
class LoaderStatusTest {

    @Test
    void shouldContainAllExpectedValues() {
        var values = LoaderStatus.values();
        assertEquals(4, values.length);

        assertArrayEquals(new LoaderStatus[]{
                LoaderStatus.OK,
                LoaderStatus.ERROR,
                LoaderStatus.LOADING,
                LoaderStatus.UNDEFINED
        }, values);
    }

    @Test
    void shouldProvideCorrectStringRepresentation() {
        assertEquals("ok", LoaderStatus.OK.toString());
        assertEquals("error", LoaderStatus.ERROR.toString());
        assertEquals("loading", LoaderStatus.LOADING.toString());
        assertEquals("undefined", LoaderStatus.UNDEFINED.toString());
    }

    @Test
    void shouldProvideValueOfFunctionality() {
        assertEquals(LoaderStatus.OK, LoaderStatus.valueOf("OK"));
        assertEquals(LoaderStatus.ERROR, LoaderStatus.valueOf("ERROR"));
        assertEquals(LoaderStatus.LOADING, LoaderStatus.valueOf("LOADING"));
        assertEquals(LoaderStatus.UNDEFINED, LoaderStatus.valueOf("UNDEFINED"));
    }

    @Test
    void shouldThrowExceptionForInvalidValue() {
        assertThrows(IllegalArgumentException.class, () -> LoaderStatus.valueOf("INVALID_STATUS"));
        assertThrows(IllegalArgumentException.class, () -> LoaderStatus.valueOf(""));
        assertThrows(IllegalArgumentException.class, () -> LoaderStatus.valueOf("ok"));
        assertThrows(IllegalArgumentException.class, () -> LoaderStatus.valueOf("error"));
    }

    @Test
    void shouldHandleNullValue() {
        assertThrows(NullPointerException.class, () -> LoaderStatus.valueOf(null));
    }

    @Test
    void shouldProvideConsistentOrdinalValues() {
        assertEquals(0, LoaderStatus.OK.ordinal());
        assertEquals(1, LoaderStatus.ERROR.ordinal());
        assertEquals(2, LoaderStatus.LOADING.ordinal());
        assertEquals(3, LoaderStatus.UNDEFINED.ordinal());
    }

    @Test
    void shouldDistinguishBetweenNameAndToString() {
        assertEquals("OK", LoaderStatus.OK.name());
        assertEquals("ok", LoaderStatus.OK.toString());

        assertEquals("ERROR", LoaderStatus.ERROR.name());
        assertEquals("error", LoaderStatus.ERROR.toString());

        assertEquals("LOADING", LoaderStatus.LOADING.name());
        assertEquals("loading", LoaderStatus.LOADING.toString());

        assertEquals("UNDEFINED", LoaderStatus.UNDEFINED.name());
        assertEquals("undefined", LoaderStatus.UNDEFINED.toString());
    }
}