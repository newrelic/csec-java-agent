package com.newrelic.agent.security.intcodeagent.websocket;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;

import java.lang.reflect.Method;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

public class CustomTrustStoreManagerUtils {
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static Set<X509Certificate> getTrustedCerts() throws Exception {
        try {
            Class<?> TrustStoreManager = Class.forName("sun.security.ssl.TrustStoreManager");
            Method getTrustedCerts = TrustStoreManager.getMethod("getTrustedCerts");
            getTrustedCerts.setAccessible(true);
            return (Set<X509Certificate>) getTrustedCerts.invoke(null);
        } catch (Throwable e) {
            logger.log(LogLevel.FINEST, "Unable to load jvm default x509 certificate trust store : " + e.toString(),
                    CustomTrustStoreManagerUtils.class.getName());
        }
        return Collections.emptySet();
    }
}
