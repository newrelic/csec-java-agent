package com.newrelic.agent.security.intcodeagent.apache.httpclient;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import org.apache.http.*;
import org.apache.http.protocol.HttpContext;

import java.io.IOException;

public class ReplayResponseLoggingInterceptor implements HttpResponseInterceptor {
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    @Override
    public void process(HttpResponse httpResponse, HttpContext httpContext) throws HttpException, IOException {
        logger.log(LogLevel.FINEST, String.format("Response of the replay request %s", httpResponse.getStatusLine()), IastHttpClient.class.getName());
        IastHttpClient.getInstance().setConnected(httpResponse.getStatusLine().getStatusCode() != 503 && httpResponse.getStatusLine().getStatusCode() != 504);
    }
}
