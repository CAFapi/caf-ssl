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

import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.ConfigurableEnvironment;

/**
 * Registers the TLS security providers required for PQC hybrid key exchange during the earliest
 * phase of Spring Boot start-up.
 *
 * <p>An {@link EnvironmentPostProcessor} runs while the {@code Environment} is being prepared, which
 * is well before the application context is refreshed and before the embedded servlet container
 * creates its {@code SSLContext}. This guarantees the BouncyCastle providers are in place in time
 * for the TLS endpoint. The processor is discovered automatically via {@code META-INF/spring.factories},
 * so a service only needs to add the {@code caf-ssl-spring} dependency.</p>
 */
public final class PqcTlsEnvironmentPostProcessor implements EnvironmentPostProcessor
{
    @Override
    public void postProcessEnvironment(final ConfigurableEnvironment environment, final SpringApplication application)
    {
        SpringSslProvider.configure();
    }
}