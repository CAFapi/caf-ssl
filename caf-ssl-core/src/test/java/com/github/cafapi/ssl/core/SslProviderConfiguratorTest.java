/*
 * Copyright 2024-2026 Open Text.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.cafapi.ssl.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;

final class SslProviderConfiguratorTest
{
    @Test
    void useBouncyCastlePolicyAlwaysRegisters()
    {
        assertTrue(SslProviderConfigurator.shouldUseBouncyCastle("UseBouncyCastle", true));
        assertTrue(SslProviderConfigurator.shouldUseBouncyCastle("UseBouncyCastle", false));
    }

    @Test
    void useJvmDefaultPolicyNeverRegisters()
    {
        assertFalse(SslProviderConfigurator.shouldUseBouncyCastle("UseJvmDefault", true));
        assertFalse(SslProviderConfigurator.shouldUseBouncyCastle("UseJvmDefault", false));
    }

    @Test
    void ifNeededPolicyFollowsRuntimeSupport()
    {
        assertFalse(SslProviderConfigurator.shouldUseBouncyCastle("UseBouncyCastleIfNeededForPqc", true));
        assertTrue(SslProviderConfigurator.shouldUseBouncyCastle("UseBouncyCastleIfNeededForPqc", false));
    }

    @Test
    void nullEmptyAndBlankDefaultToIfNeeded()
    {
        assertFalse(SslProviderConfigurator.shouldUseBouncyCastle(null, true));
        assertTrue(SslProviderConfigurator.shouldUseBouncyCastle(null, false));
        assertTrue(SslProviderConfigurator.shouldUseBouncyCastle("", false));
        assertFalse(SslProviderConfigurator.shouldUseBouncyCastle("", true));
        assertTrue(SslProviderConfigurator.shouldUseBouncyCastle("   ", false));
        assertFalse(SslProviderConfigurator.shouldUseBouncyCastle("   ", true));
    }

    @Test
    void policyMatchingIsCaseInsensitiveAndTrimmed()
    {
        assertTrue(SslProviderConfigurator.shouldUseBouncyCastle("  usebouncycastle  ", false));
        assertFalse(SslProviderConfigurator.shouldUseBouncyCastle("USEJVMDEFAULT", true));
        assertFalse(SslProviderConfigurator.shouldUseBouncyCastle("  usebouncycastleifneededforpqc  ", true));
    }

    @Test
    void unknownPolicyThrows()
    {
        assertThrows(IllegalArgumentException.class,
                () -> SslProviderConfigurator.shouldUseBouncyCastle("Nonsense", false));
    }

    @Test
    void runtimePqcDetectionIsConsistentWithSupportedNamedGroups() throws Exception
    {
        final SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        final String[] namedGroups = sslContext.getSupportedSSLParameters().getNamedGroups();

        assertNotNull(namedGroups, "Default TLS provider should expose its supported named groups (Java 20+)");
        assertTrue(namedGroups.length > 0, "Default TLS provider should support at least one named group");

        final boolean expected = Arrays.stream(namedGroups)
                .anyMatch(SslProviderConfigurator.PQC_NAMED_GROUP::equalsIgnoreCase);
        assertEquals(expected, SslProviderConfigurator.isRuntimePqcSupported());
    }
}
