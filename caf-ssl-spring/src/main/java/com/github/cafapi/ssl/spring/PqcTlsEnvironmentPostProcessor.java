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
package com.github.cafapi.ssl.spring;

import com.github.cafapi.ssl.core.SslProviderConfigurator;
import java.util.Properties;
import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertiesPropertySource;

/** Registers PQC providers and default TLS ciphers during Spring Boot start-up. */
public final class PqcTlsEnvironmentPostProcessor implements EnvironmentPostProcessor
{
    private static final String SERVER_SSL_CIPHERS_PROPERTY = "server.ssl.ciphers";
    private static final String DEFAULT_CIPHERS_SOURCE = "caf-ssl-approved-ciphers";

    @Override
    public void postProcessEnvironment(final ConfigurableEnvironment environment, final SpringApplication application)
    {
        SslProviderConfigurator.configure(true);

        if (environment.getProperty(SERVER_SSL_CIPHERS_PROPERTY) == null) {
            final MutablePropertySources propertySources = environment.getPropertySources();
            final Properties properties = new Properties();
            properties.setProperty(SERVER_SSL_CIPHERS_PROPERTY, SslProviderConfigurator.APPROVED_TLS_CIPHER_SUITES);
            propertySources.addLast(new PropertiesPropertySource(DEFAULT_CIPHERS_SOURCE, properties));
        }
    }
}
