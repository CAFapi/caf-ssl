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

import com.github.cafapi.common.util.secret.SecretUtil;
import io.dropwizard.core.Configuration;
import io.dropwizard.core.ConfiguredBundle;
import io.dropwizard.core.server.DefaultServerFactory;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;
import io.dropwizard.jetty.ConnectorFactory;
import io.dropwizard.jetty.HttpsConnectorFactory;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

enum DropWizardSslBundle implements ConfiguredBundle<Configuration>
{
    INSTANCE;

    private boolean useBouncyCastle;
    private static final String SSL_KEYSTORE_PATH = System.getenv("SSL_KEYSTORE_PATH");
    private static final String SSL_KEYSTORE = System.getenv("SSL_KEYSTORE");
    private static final String SSL_CERT_ALIAS = System.getenv("SSL_CERT_ALIAS");
    private static final String SSL_KEYSTORE_TYPE = System.getenv("SSL_KEYSTORE_TYPE");
    private static final String SSL_VALIDATE_CERTS = System.getenv("SSL_VALIDATE_CERTS");
    private static final String SSL_DISABLE_SNI_HOST_CHECK = System.getenv("SSL_DISABLE_SNI_HOST_CHECK");
    private static final String HTTPS_PORT = System.getenv("HTTPS_PORT");
    private static final String SSL_JCE_PROVIDER_POLICY = System.getenv("SSL_JCE_PROVIDER_POLICY");
    private static final String POLICY_USE_BOUNCY_CASTLE = "UseBouncyCastle";
    private static final String POLICY_USE_BOUNCY_CASTLE_IF_NEEDED_FOR_PQC = "UseBouncyCastleIfNeededForPqc";
    private static final String POLICY_USE_JVM_DEFAULT = "UseJvmDefault";
    private static final String JAVA_SPECIFICATION_VERSION = System.getProperty("java.specification.version");
    private static final int MIN_PQC_JAVA_SPEC_VERSION = 27;

    @Override
    public void initialize(final Bootstrap<?> bootstrap)
    {
        useBouncyCastle = shouldUseBouncyCastle();

        if (useBouncyCastle) {
            registerBouncyCastleProviders();
        }
    }

    @Override
    public void run(final Configuration configuration, final Environment environment) throws Exception
    {
        final String sslKeystorePassword = SecretUtil.getSecret("SSL_KEYSTORE_PASSWORD");

        if (!isHttpsEnabled(sslKeystorePassword)) {
            return;
        }

        final HttpsConnectorFactory httpsConnectorFactory = new HttpsConnectorFactory();

        httpsConnectorFactory.setPort(isNotNullOrEmpty(HTTPS_PORT) ? Integer.parseInt(HTTPS_PORT) : 8443);
        httpsConnectorFactory.setKeyStorePath(SSL_KEYSTORE_PATH + "/" + SSL_KEYSTORE);
        httpsConnectorFactory.setKeyStorePassword(sslKeystorePassword);
        httpsConnectorFactory.setKeyStoreType(isNotNullOrEmpty(SSL_KEYSTORE_TYPE) ? SSL_KEYSTORE_TYPE : "JKS");
        httpsConnectorFactory.setCertAlias(SSL_CERT_ALIAS);
        httpsConnectorFactory.setValidateCerts(
            isNotNullOrEmpty(SSL_VALIDATE_CERTS)
            && Boolean.parseBoolean(SSL_VALIDATE_CERTS));
        httpsConnectorFactory.setDisableSniHostCheck(
            isNotNullOrEmpty(SSL_DISABLE_SNI_HOST_CHECK)
            && Boolean.parseBoolean(SSL_DISABLE_SNI_HOST_CHECK));

        if (useBouncyCastle) {
            httpsConnectorFactory.setJceProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
        }

        final DefaultServerFactory serverFactory = (DefaultServerFactory) configuration.getServerFactory();
        final List<ConnectorFactory> applicationConnectors = serverFactory.getApplicationConnectors();
        try {
            applicationConnectors.add(httpsConnectorFactory);
        } catch (final UnsupportedOperationException ex) {
            final List<ConnectorFactory> newApplicationConnectors = new ArrayList<>(applicationConnectors);
            newApplicationConnectors.add(httpsConnectorFactory);
            serverFactory.setApplicationConnectors(newApplicationConnectors);
        }
    }

    private static boolean isHttpsEnabled(final String sslKeystorePassword)
    {
        return isNotNullOrEmpty(SSL_KEYSTORE_PATH)
            && isNotNullOrEmpty(SSL_KEYSTORE)
            && isNotNullOrEmpty(sslKeystorePassword)
            && isNotNullOrEmpty(SSL_CERT_ALIAS);
    }

    private static boolean isNotNullOrEmpty(final String value)
    {
        return value != null && !value.isEmpty();
    }

    private static void registerBouncyCastleProviders()
    {
        final BouncyCastleProvider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);
        Security.addProvider(new BouncyCastleJsseProvider(bcProvider));
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
        try {
            return Integer.parseInt(JAVA_SPECIFICATION_VERSION) >= MIN_PQC_JAVA_SPEC_VERSION;
        } catch (final NumberFormatException ex) {
            return false;
        }
    }
}
