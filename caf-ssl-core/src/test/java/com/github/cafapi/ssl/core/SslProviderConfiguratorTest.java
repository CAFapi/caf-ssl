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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
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
    void isRuntimePqcSupportedNeverThrows()
    {
        // Fail-safe contract: probing the runtime must never abort startup, whatever the active provider.
        SslProviderConfigurator.isRuntimePqcSupported();
    }

    @Test
    void registerPromotesExistingJsseProviderToHighestPriority()
    {
        Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);

        // Append BCJSSE below the JVM providers, then confirm it is not the highest priority.
        SslProviderConfigurator.registerBouncyCastleProviders(false);
        assertFalse(isHighestPriority(BouncyCastleJsseProvider.PROVIDER_NAME),
                "Appended BCJSSE should not start at the highest priority");

        // A subsequent high-priority registration must promote the already-registered provider.
        SslProviderConfigurator.registerBouncyCastleProviders(true);
        assertTrue(isHighestPriority(BouncyCastleJsseProvider.PROVIDER_NAME),
                "BCJSSE should be promoted to the highest priority");
    }

    @Test
    void bouncyCastleNegotiatesPqcHybridGroupOverRealHandshake() throws Exception
    {
        SslProviderConfigurator.registerBouncyCastleProviders(true);

        final SSLContext sslContext = newBouncyCastleContext();
        final byte[] payload = {7, 11, 42};

        try (SSLServerSocket serverSocket = openPqcServer(sslContext)) {
            final int port = serverSocket.getLocalPort();

            final Thread serverThread = new Thread(() -> {
                try (SSLSocket accepted = (SSLSocket) serverSocket.accept()) {
                    final byte[] received = accepted.getInputStream().readNBytes(payload.length);
                    accepted.getOutputStream().write(received);
                    accepted.getOutputStream().flush();
                } catch (final Exception ignored) {
                    // The client assertions surface any handshake failure.
                }
            });
            serverThread.setDaemon(true);
            serverThread.start();

            final SSLSocketFactory socketFactory = sslContext.getSocketFactory();
            try (SSLSocket client = (SSLSocket) socketFactory.createSocket(InetAddress.getLoopbackAddress(), port)) {
                restrictToPqcGroup(client);
                client.startHandshake();

                assertEquals("TLSv1.3", client.getSession().getProtocol());

                client.getOutputStream().write(payload);
                client.getOutputStream().flush();
                final byte[] echoed = client.getInputStream().readNBytes(payload.length);
                assertArrayEquals(payload, echoed, "PQC-restricted TLS session should carry application data");
            }

            serverThread.join(5000);
        }
    }

    private static SSLServerSocket openPqcServer(final SSLContext sslContext) throws Exception
    {
        final SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
        final SSLServerSocket serverSocket =
                (SSLServerSocket) factory.createServerSocket(0, 1, InetAddress.getLoopbackAddress());
        final SSLParameters parameters = serverSocket.getSSLParameters();
        parameters.setNamedGroups(new String[]{SslProviderConfigurator.PQC_NAMED_GROUP});
        parameters.setProtocols(new String[]{"TLSv1.3"});
        serverSocket.setSSLParameters(parameters);
        return serverSocket;
    }

    private static void restrictToPqcGroup(final SSLSocket socket)
    {
        final SSLParameters parameters = socket.getSSLParameters();
        parameters.setNamedGroups(new String[]{SslProviderConfigurator.PQC_NAMED_GROUP});
        parameters.setProtocols(new String[]{"TLSv1.3"});
        socket.setSSLParameters(parameters);
    }

    private static SSLContext newBouncyCastleContext() throws Exception
    {
        final Provider bcProvider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        final char[] password = "changeit".toCharArray();

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", bcProvider);
        keyPairGenerator.initialize(2048);
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        final long now = System.currentTimeMillis();
        final X500Principal subject = new X500Principal("CN=localhost");
        final X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(bcProvider)
                .getCertificate(new JcaX509v3CertificateBuilder(
                        subject,
                        BigInteger.valueOf(now),
                        new Date(now - 86_400_000L),
                        new Date(now + 86_400_000L),
                        subject,
                        keyPair.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withRSA")
                                .setProvider(bcProvider)
                                .build(keyPair.getPrivate())));

        final KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("pqc", keyPair.getPrivate(), password, new X509Certificate[]{certificate});

        final KeyManagerFactory keyManagerFactory =
                KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
        keyManagerFactory.init(keyStore, password);
        final TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
        trustManagerFactory.init(keyStore);

        final SSLContext sslContext = SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
        return sslContext;
    }

    private static boolean isHighestPriority(final String providerName)
    {
        final Provider[] providers = Security.getProviders();
        return providers.length > 0 && providerName.equals(providers[0].getName());
    }
}
