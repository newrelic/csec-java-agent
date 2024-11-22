package com.newrelic.agent.security.intcodeagent.apache.httpclient;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.protocol.HttpContext;

import java.text.MessageFormat;
import java.util.logging.Level;

public class ApacheProxyManager {
    private final HttpHost proxy;
    private final Credentials proxyCredentials;
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public ApacheProxyManager(String proxyHost, Integer proxyPort, String proxyScheme, String proxyUser, String proxyPassword) {
        if (proxyHost != null && proxyPort != null) {
            logger.log(LogLevel.FINE, MessageFormat.format("Using proxy host {0}:{1}", proxyHost, Integer.toString(proxyPort)), ApacheProxyManager.class.getName());
            proxy = new HttpHost(proxyHost, proxyPort, proxyScheme);
            proxyCredentials = getProxyCredentials(proxyUser, proxyPassword);
        } else {
            proxy = null;
            proxyCredentials = null;
        }
    }

    private Credentials getProxyCredentials(final String proxyUser, final String proxyPass) {
        if (proxyUser != null && proxyPass != null) {
            logger.log(LogLevel.INFO, MessageFormat.format("Setting Proxy Authenticator for user {0}", proxyUser), ApacheProxyManager.class.getName());
            return new UsernamePasswordCredentials(proxyUser, proxyPass);
        }
        return null;
    }

    public HttpHost getProxy() {
        return proxy;
    }

    public HttpContext updateContext(HttpClientContext httpClientContext) {
        if (proxy != null && proxyCredentials != null) {
            CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            credentialsProvider.setCredentials(new AuthScope(proxy), proxyCredentials);
            httpClientContext.setCredentialsProvider(credentialsProvider);
        }

        return httpClientContext;
    }
}
