package com.newrelic.agent.security.intcodeagent.websocket;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;

public class NRSSLFactory {
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private NRSSLFactory() {
//        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
//        keyStore.load(null, null);
//        CertificateFactory cf = CertificateFactory.getInstance("X.509");
//
//        for (Iterator<Path> it = Files.list(Paths.get("cacerts/")).iterator(); it.hasNext(); ) {
//            Path path = it.next();
//            try {
//                if (!StringUtils.endsWithIgnoreCase(path.toFile().getName(), ".crt")) {
//                    continue;
//                }
//
//                Certificate certificate = cf.generateCertificate(FileUtils.openInputStream(path.toFile()));
//                keyStore.setCertificateEntry(path.toFile().getName(), certificate);
//                logger.info("Loaded CA trust certificate : {}", path);
//            } catch (Exception e) {
//                logger.error("Error while loading CA trust certificate : {} : {} : {}", path, e.getMessage(), e.getCause());
//            }
//        }
//        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
//        trustManagerFactory.init(keyStore);
//
//        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
//        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
//        SSLConnectionSocketFactory sslsf;
//        if (Runner.skipVerify) {
//            SSLContextBuilder builder = SSLContexts.custom();
//            builder.loadTrustMaterial(null, new TrustStrategy() {
//                @Override
//                public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
//                    return true;
//                }
//            });
//            sslsf = new SSLConnectionSocketFactory(builder.build(), NoopHostnameVerifier.INSTANCE);
//        } else {
//            sslsf = new SSLConnectionSocketFactory(sslContext);
//        }
    }
}
