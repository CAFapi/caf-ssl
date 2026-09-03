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
import org.apache.catalina.connector.Connector;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Auto-configuration that registers caf-ssl Spring beans. */
@Configuration
public class CafSslSpringAutoConfiguration
{
    /**
     * Applies the configured TLS cipher suite list to Tomcat SSL host configs on both pre-added
     * additional connectors and connectors customized during factory startup.
     */
    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> cafSslTomcatCipherCustomizer()
    {
        return factory -> {
            final String configuredCiphers = SslProviderConfigurator.resolveApprovedCipherSuites();
            for (final Connector connector : factory.getAdditionalConnectors()) {
                connector.findSslHostConfigs();
                for (final var sslHostConfig : connector.findSslHostConfigs()) {
                    sslHostConfig.setCiphers(configuredCiphers);
                }
            }
            factory.addConnectorCustomizers(connector -> {
                for (final var sslHostConfig : connector.findSslHostConfigs()) {
                    sslHostConfig.setCiphers(configuredCiphers);
                }
            });
        };
    }
}
