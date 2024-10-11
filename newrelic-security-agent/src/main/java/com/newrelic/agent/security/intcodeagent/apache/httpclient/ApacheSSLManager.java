/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.newrelic.agent.security.intcodeagent.apache.httpclient;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.utils.ResourceUtils;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.apache.http.ssl.SSLContextBuilder;

import javax.net.ssl.SSLContext;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedList;
import java.util.logging.Level;

public class ApacheSSLManager {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static SSLContext createSSLContext(String caBundlePath) {
        SSLContextBuilder sslContextBuilder = new SSLContextBuilder();
        try {
            if (StringUtils.isNotBlank(caBundlePath)) {
                logger.log(LogLevel.INFO, String.format("Using ca_bundle_path: %s", caBundlePath), ApacheSSLManager.class.getName());
                sslContextBuilder.loadTrustMaterial(getKeyStore(caBundlePath), null);
            } else {
                logger.log(LogLevel.INFO, "Using nr custom ca from agent resources", ApacheSSLManager.class.getName());
                sslContextBuilder.loadTrustMaterial(getKeyStore(ResourceUtils.getResourceStreamFromAgentJar("nr-custom-ca.pem")), null);
            }
            return sslContextBuilder.build();
        } catch (Exception e) {
            logger.log(LogLevel.WARNING, "Unable to create SSL context", e , ApacheSSLManager.class.getName());
            return null;
        }
    }

    private static KeyStore getKeyStore(InputStream caBundleResourceStream) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        logger.log(LogLevel.FINER, "SSL Keystore Provider: " + keystore.getProvider().getName(), ApacheSSLManager.class.getName());

        Collection<X509Certificate> caCerts = new LinkedList<>();

        try (InputStream is = new BufferedInputStream(caBundleResourceStream)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            while (is.available() > 0) {
                try {
                    caCerts.add((X509Certificate) cf.generateCertificate(is));
                } catch (Throwable t) {
                    logger.log(LogLevel.SEVERE,
                            "Unable to generate ca_bundle_path certificate. Verify the certificate format. Will not process further certs.", t, ApacheSSLManager.class.getName());
                    break;
                }
            }
        }

        logger.log(
                !caCerts.isEmpty() ? LogLevel.INFO : LogLevel.SEVERE,
                String.format("Read ca_bundle_path and found %s certificates.",
                        caCerts.size()), ApacheSSLManager.class.getName());

        // Initialize the keystore
        keystore.load(null, null);

        int i = 1;
        for (X509Certificate caCert : caCerts) {
            if (caCert != null) {
                String alias = "ca_bundle_path_" + i;
                keystore.setCertificateEntry(alias, caCert);

                logger.log(LogLevel.FINEST, String.format("Installed certificate {0} at alias: {1}", i, alias), ApacheSSLManager.class.getName());
            }
            i++;
        }
        return keystore;
    }

    private static KeyStore getKeyStore(String caBundlePath)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        logger.log(LogLevel.FINEST, String.format("Checking ca_bundle_path at: %s", caBundlePath), ApacheSSLManager.class.getName());
        return getKeyStore(new FileInputStream(caBundlePath));
    }
}
