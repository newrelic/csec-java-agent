package com.newrelic.agent.security.intcodeagent.apache.httpclient;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.protocol.HttpContext;

import java.io.IOException;

public class ReplayRequestLoggingInterceptor implements HttpRequestInterceptor {
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    @Override
    public void process(HttpRequest httpRequest, HttpContext httpContext) throws HttpException, IOException {
        logger.log(LogLevel.FINEST, String.format("Replaying request %s", httpRequest.getRequestLine()), IastHttpClient.class.getName());
    }
}
