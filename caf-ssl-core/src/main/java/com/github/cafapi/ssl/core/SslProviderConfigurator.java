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

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.SSLContext;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Shared logic for selecting the TLS JCE provider and, when required, registering BouncyCastle so a
 * service can negotiate the {@code X25519MLKEM768} post-quantum hybrid key exchange on its TLS endpoint.
 *
 * <p>The behaviour is driven by the {@value #SSL_JCE_PROVIDER_POLICY_ENV} environment variable:</p>
 * <ul>
 *   <li>{@code UseBouncyCastleIfNeededForPqc} (default) - register BouncyCastle only when the JVM's own
 *       TLS stack cannot negotiate the PQC hybrid group, and only when the JVM is not running in FIPS mode.</li>
 *   <li>{@code UseBouncyCastle} - always register BouncyCastle.</li>
 *   <li>{@code UseJvmDefault} - never register BouncyCastle; rely on the JVM's default providers.</li>
 * </ul>
 *
 * <p>FIPS and PQC are mutually exclusive: BouncyCastle's PQC support is not FIPS-certified, so the default
 * and {@code UseBouncyCastleIfNeededForPqc} policies fall back to JVM defaults when the host is detected to be
 * running in FIPS mode (see {@link #isFipsEnabled()}). No extra configuration is required for this; an explicit
 * {@code UseBouncyCastle} policy still overrides it.</p>
 *
 * <p>This class carries no Dropwizard or Spring dependency so both bundles can share it.</p>
 */
public final class SslProviderConfigurator
{
    /**
     * The TLS named group for the post-quantum hybrid key exchange.
     */
    public static final String PQC_NAMED_GROUP = "X25519MLKEM768";

    /**
     * The environment variable that selects the JCE provider policy.
     */
    public static final String SSL_JCE_PROVIDER_POLICY_ENV = "SSL_JCE_PROVIDER_POLICY";

    /**
     * The environment variable that overrides the default approved TLS cipher suite list. Value is a
     * comma-separated list of cipher suite names, for example {@code TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384}.
     */
    public static final String CAF_SSL_CIPHER_SUITES_ENV = "CAF_SSL_CIPHER_SUITES";

    /** Approved TLS cipher suites used when {@value #CAF_SSL_CIPHER_SUITES_ENV} is not set. */
    public static final String APPROVED_TLS_CIPHER_SUITES = String.join(",",
            List.of(
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
            ));

    static final String POLICY_USE_BOUNCY_CASTLE = "UseBouncyCastle";
    static final String POLICY_USE_BOUNCY_CASTLE_IF_NEEDED_FOR_PQC = "UseBouncyCastleIfNeededForPqc";
    static final String POLICY_USE_JVM_DEFAULT = "UseJvmDefault";

    /** Linux kernel flag consulted to detect FIPS mode. */
    static final Path LINUX_FIPS_FLAG_FILE = Path.of("/proc/sys/crypto/fips_enabled");

    private static final Logger LOGGER = LoggerFactory.getLogger(SslProviderConfigurator.class);

    private SslProviderConfigurator()
    {
    }

    /**
     * Reads {@value #SSL_JCE_PROVIDER_POLICY_ENV}, registers the BouncyCastle providers when required, and
     * reports whether BouncyCastle was used. Safe to call more than once; registration is idempotent.
     *
     * @param insertJsseProviderAtHighestPriority when {@code true} the BouncyCastle JSSE provider is inserted
     *        at the highest priority (needed when the container resolves the default {@code SSLContext});
     *        when {@code false} it is appended (the caller assigns BCJSSE explicitly).
     * @return {@code true} if BouncyCastle was registered
     */
    public static boolean configure(final boolean insertJsseProviderAtHighestPriority)
    {
        final boolean useBouncyCastle = shouldUseBouncyCastle(System.getenv(SSL_JCE_PROVIDER_POLICY_ENV));
        if (useBouncyCastle) {
            registerBouncyCastleProviders(insertJsseProviderAtHighestPriority);
            LOGGER.info("caf-ssl: registered BouncyCastle providers for PQC TLS ({})", PQC_NAMED_GROUP);
        } else {
            LOGGER.info("caf-ssl: using JVM default TLS providers");
        }
        return useBouncyCastle;
    }

    /**
     * Resolves the approved TLS cipher suite list, honouring {@value #CAF_SSL_CIPHER_SUITES_ENV} when set.
     *
     * @return a comma-separated list of TLS cipher suite names
     */
    public static String resolveApprovedCipherSuites()
    {
        final String override = System.getenv(CAF_SSL_CIPHER_SUITES_ENV);
        return (override == null || override.isBlank()) ? APPROVED_TLS_CIPHER_SUITES : override.trim();
    }

    /**
     * Resolves the policy, probing the runtime for PQC support and FIPS mode when the policy defers to them.
     *
     * @param policy the raw {@value #SSL_JCE_PROVIDER_POLICY_ENV} value (may be {@code null})
     * @return {@code true} if BouncyCastle should be registered
     */
    public static boolean shouldUseBouncyCastle(final String policy)
    {
        return shouldUseBouncyCastle(policy, isRuntimePqcSupported(), isFipsEnabled());
    }

    /**
     * Pure policy resolution, independent of the runtime, so it can be unit tested in isolation.
     *
     * @param policy the raw {@value #SSL_JCE_PROVIDER_POLICY_ENV} value (may be {@code null})
     * @param runtimePqcSupported whether the runtime can already negotiate the PQC hybrid group
     * @param fipsEnabled whether the host is running in FIPS mode
     * @return {@code true} if BouncyCastle should be registered
     */
    public static boolean shouldUseBouncyCastle(final String policy, final boolean runtimePqcSupported,
            final boolean fipsEnabled)
    {
        final String normalizedPolicy = policy == null ? null : policy.trim();

        if (normalizedPolicy == null || normalizedPolicy.isEmpty()
                || POLICY_USE_BOUNCY_CASTLE_IF_NEEDED_FOR_PQC.equalsIgnoreCase(normalizedPolicy)) {
            return !fipsEnabled && !runtimePqcSupported;
        }

        if (POLICY_USE_BOUNCY_CASTLE.equalsIgnoreCase(normalizedPolicy)) {
            return true;
        }

        if (POLICY_USE_JVM_DEFAULT.equalsIgnoreCase(normalizedPolicy)) {
            return false;
        }

        throw new IllegalArgumentException("Unknown " + SSL_JCE_PROVIDER_POLICY_ENV + " value: " + policy);
    }

    /**
     * Asks the active JSSE provider whether it can negotiate the PQC hybrid group. Fails safe: if the TLS
     * layer cannot be inspected, returns {@code false} so BouncyCastle is registered rather than aborting
     * startup. Requires {@code SSLParameters.getNamedGroups()} (Java 20+).
     *
     * @return {@code true} if the runtime already supports the PQC hybrid group
     */
    public static boolean isRuntimePqcSupported()
    {
        try {
            final SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);

            final String[] namedGroups = sslContext.getSupportedSSLParameters().getNamedGroups();
            return namedGroups != null && Arrays.stream(namedGroups).anyMatch(PQC_NAMED_GROUP::equalsIgnoreCase);
        } catch (final GeneralSecurityException e) {
            LOGGER.warn("caf-ssl: unable to inspect the JVM TLS provider; assuming PQC is not supported", e);
            return false;
        }
    }

    /**
     * Detects whether the JVM is running in FIPS mode
     */
    public static boolean isFipsEnabled()
    {
        final String osName = System.getProperty("os.name", "");
        if (!osName.toLowerCase(Locale.ROOT).contains("linux")) {
            return false;
        }

        try {
            return Files.exists(LINUX_FIPS_FLAG_FILE)
                    && "1".equals(Files.readString(LINUX_FIPS_FLAG_FILE).trim());
        } catch (final Exception e) {
            LOGGER.warn("caf-ssl: unable to read {}; assuming FIPS is not enabled", LINUX_FIPS_FLAG_FILE, e);
            return false;
        }
    }

    /**
     * Registers the BouncyCastle JCE and JSSE providers. Idempotent: existing providers are reused and not
     * duplicated. When {@code insertJsseProviderAtHighestPriority} is {@code true}, an already-registered
     * BCJSSE provider that is not at the top is promoted, so the container's default {@code SSLContext}
     * always resolves BCJSSE rather than a JVM provider that lacks the PQC group.
     *
     * @param insertJsseProviderAtHighestPriority when {@code true} the JSSE provider is inserted at position 1
     */
    public static void registerBouncyCastleProviders(final boolean insertJsseProviderAtHighestPriority)
    {
        final Provider existingBcProvider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        final Provider bcProvider = existingBcProvider == null
                ? new BouncyCastleProvider()
                : existingBcProvider;

        if (existingBcProvider == null) {
            Security.addProvider(bcProvider);
        }

        final Provider existingJsseProvider = Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
        if (existingJsseProvider == null) {
            final BouncyCastleJsseProvider jsseProvider = new BouncyCastleJsseProvider(bcProvider);
            if (insertJsseProviderAtHighestPriority) {
                Security.insertProviderAt(jsseProvider, 1);
            } else {
                Security.addProvider(jsseProvider);
            }
        } else if (insertJsseProviderAtHighestPriority && !isHighestPriority(existingJsseProvider)) {
            Security.removeProvider(existingJsseProvider.getName());
            Security.insertProviderAt(existingJsseProvider, 1);
        }
    }

    private static boolean isHighestPriority(final Provider provider)
    {
        final Provider[] providers = Security.getProviders();
        return providers.length > 0 && providers[0] == provider;
    }
}
