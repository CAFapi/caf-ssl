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

import io.dropwizard.jetty.HttpsConnectorFactory;
import javax.net.ssl.SSLParameters;
import org.eclipse.jetty.util.ssl.SslContextFactory;

/**
 * An {@link HttpsConnectorFactory} whose connector lets the client choose the cipher suite and only offers the given TLS named groups
 * (curves). Jetty has no named group setting, so the groups are applied to each {@code SSLEngine}.
 */
final class CafHttpsConnectorFactory extends HttpsConnectorFactory
{
    private final String[] namedGroups;

    CafHttpsConnectorFactory(final String[] namedGroups)
    {
        this.namedGroups = namedGroups.clone();
    }

    @Override
    protected SslContextFactory.Server configureSslContextFactory(final SslContextFactory sslContextFactory)
    {
        configure(sslContextFactory);
        // Dropwizard builds the connector from the factory returned here, so return one that restricts the named
        // groups. The factory passed in is still configured because an SSL reload dry run uses it to check that the
        // new keystore loads.
        return configure(new NamedGroupsSslContextFactory(namedGroups));
    }

    private SslContextFactory.Server configure(final SslContextFactory sslContextFactory)
    {
        final SslContextFactory.Server factory = super.configureSslContextFactory(sslContextFactory);
        // Client chooses the cipher, as required by the intermediate TLS profile.
        factory.setUseCipherSuitesOrder(false);
        return factory;
    }

    private static final class NamedGroupsSslContextFactory extends SslContextFactory.Server
    {
        private final String[] namedGroups;

        NamedGroupsSslContextFactory(final String[] namedGroups)
        {
            this.namedGroups = namedGroups;
        }

        @Override
        public SSLParameters customize(final SSLParameters sslParams)
        {
            final SSLParameters customized = super.customize(sslParams);
            customized.setNamedGroups(namedGroups);
            return customized;
        }
    }
}
