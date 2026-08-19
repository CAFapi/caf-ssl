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

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import javax.net.ssl.SSLContext;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Configures the JCE/JSSE security providers so that a Spring Boot service can negotiate the
 * {@code X25519MLKEM768} post-quantum hybrid key exchange on its TLS endpoint.
 *
 * <p>The behavior is controlled by the {@code SSL_JCE_PROVIDER_POLICY} environment variable:</p>
 * <ul>
 *   <li>{@code UseBouncyCastleIfNeededForPqc} (default) - register BouncyCastle only when the JVM's
 *       own TLS stack cannot negotiate the PQC hybrid group.</li>
 *   <li>{@code UseBouncyCastle} - always register BouncyCastle.</li>
 *   <li>{@code UseJvmDefault} - never register BouncyCastle; rely on the JVM's default providers.</li>
 * </ul>
 *
 * <p>This class is deliberately free of any Spring dependency so it can be invoked directly from a
 * service's {@code main} method. In practice it is triggered automatically by
 * {@link PqcTlsEnvironmentPostProcessor} during the earliest phase of Spring Boot start-up, before
 * the embedded servlet container creates its {@link SSLContext}.</p>
 */
public final class SpringSslProvider
{
    private static final Logger LOGGER = LoggerFactory.getLogger(SpringSslProvider.class);

    private static final String SSL_JCE_PROVIDER_POLICY = System.getenv("SSL_JCE_PROVIDER_POLICY");
    private static final String POLICY_USE_BOUNCY_CASTLE = "UseBouncyCastle";
    private static final String POLICY_USE_BOUNCY_CASTLE_IF_NEEDED_FOR_PQC = "UseBouncyCastleIfNeededForPqc";
    private static final String POLICY_USE_JVM_DEFAULT = "UseJvmDefault";
    private static final String PQC_NAMED_GROUP = "X25519MLKEM768";

    private SpringSslProvider()
    {
    }

    /**
     * Registers the BouncyCastle providers when required by the active {@code SSL_JCE_PROVIDER_POLICY}.
     * Safe to call more than once; provider registration is idempotent.
     */
    public static void configure()
    {
        if (shouldUseBouncyCastle()) {
            registerBouncyCastleProviders();
            LOGGER.info("caf-ssl-spring: registered BouncyCastle providers for PQC TLS (X25519MLKEM768)");
        } else {
            LOGGER.info("caf-ssl-spring: using JVM default TLS providers");
        }
    }

    private static boolean shouldUseBouncyCastle()
    {
        final String policy = SSL_JCE_PROVIDER_POLICY == null ? null : SSL_JCE_PROVIDER_POLICY.trim();

        if (policy == null || policy.isEmpty() || POLICY_USE_BOUNCY_CASTLE_IF_NEEDED_FOR_PQC.equalsIgnoreCase(policy)) {
            return !isRuntimePqcSupported();
        }

        if (POLICY_USE_BOUNCY_CASTLE.equalsIgnoreCase(policy)) {
            return true;
        }

        if (POLICY_USE_JVM_DEFAULT.equalsIgnoreCase(policy)) {
            return false;
        }

        throw new IllegalArgumentException("Unknown SSL_JCE_PROVIDER_POLICY value: " + SSL_JCE_PROVIDER_POLICY);
    }

    private static boolean isRuntimePqcSupported()
    {
        // Ask the TLS layer directly whether it supports the PQC hybrid group
        try {
            final SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);

            final String[] namedGroups = sslContext.getSupportedSSLParameters().getNamedGroups();
            return namedGroups != null && Arrays.stream(namedGroups).anyMatch(PQC_NAMED_GROUP::equalsIgnoreCase);
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("Unable to inspect the JVM TLS provider", e);
        }
    }

    private static void registerBouncyCastleProviders()
    {
        final Provider existingBcProvider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        final Provider bcProvider = existingBcProvider == null
                ? new BouncyCastleProvider()
                : existingBcProvider;

        if (existingBcProvider == null) {
            Security.addProvider(bcProvider);
        }

        // Insert the BouncyCastle JSSE provider at the highest priority so the embedded servlet
        // container's default SSLContext.getInstance("TLS") resolves to BouncyCastle, enabling the
        // X25519MLKEM768 hybrid key exchange on the TLS endpoint.
        if (Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleJsseProvider(bcProvider), 1);
        }
    }
}