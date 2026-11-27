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
package com.github.cafapi.ssl.dropwizard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.github.cafapi.ssl.core.SslProviderConfigurator;
import javax.net.ssl.SSLParameters;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.jupiter.api.Test;

final class CafHttpsConnectorFactoryTest
{
    private static final String[] NAMED_GROUPS = SslProviderConfigurator.APPROVED_TLS_NAMED_GROUPS.split(",");

    @Test
    void connectorEnginesUseApprovedNamedGroupsAndClientCipherOrder() throws Exception
    {
        final CafHttpsConnectorFactory connectorFactory = new CafHttpsConnectorFactory(NAMED_GROUPS);

        final SslContextFactory.Server sslContextFactory
            = connectorFactory.configureSslContextFactory(new SslContextFactory.Server());
        sslContextFactory.start();
        try {
            final SSLParameters parameters = sslContextFactory.newSSLEngine().getSSLParameters();

            assertArrayEquals(NAMED_GROUPS, parameters.getNamedGroups());
            assertFalse(parameters.getUseCipherSuitesOrder());
        } finally {
            sslContextFactory.stop();
        }
    }

    @Test
    void passedInFactoryIsAlsoConfigured()
    {
        final CafHttpsConnectorFactory connectorFactory = new CafHttpsConnectorFactory(NAMED_GROUPS);
        final SslContextFactory.Server passedIn = new SslContextFactory.Server();

        connectorFactory.configureSslContextFactory(passedIn);

        // An SSL reload dry run uses the factory it passes in to check that the new keystore loads.
        assertFalse(passedIn.isUseCipherSuitesOrder());
    }
}
