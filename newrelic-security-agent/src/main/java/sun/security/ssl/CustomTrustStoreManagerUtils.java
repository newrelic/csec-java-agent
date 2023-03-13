package sun.security.ssl;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

public class CustomTrustStoreManagerUtils {
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static Set<X509Certificate> getTrustedCerts() throws Exception {
        try {
            return TrustStoreManager.getTrustedCerts();
        } catch (Throwable e) {
            logger.log(LogLevel.FINE, "Unable to load jvm default x509 certificate trust store : ", e,
                    CustomTrustStoreManagerUtils.class.getName());
        }
        return Collections.emptySet();
    }
}
