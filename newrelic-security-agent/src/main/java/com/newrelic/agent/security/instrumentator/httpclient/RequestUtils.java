package com.newrelic.agent.security.instrumentator.httpclient;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import com.newrelic.api.agent.security.instrumentation.helpers.ServletHelper;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.agent.security.intcodeagent.models.FuzzRequestBean;
import okhttp3.*;
import okhttp3.Request.Builder;
import okhttp3.internal.http.HttpMethod;
import org.apache.commons.lang3.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

public class RequestUtils {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String ERROR_IN_FUZZ_REQUEST_GENERATION = "Error in fuzz request generation {}";

    public static Request generateK2Request(FuzzRequestBean httpRequest, String endpoint) {
        try {
            logger.log(LogLevel.FINER, String.format("Firing request : %s", JsonConverter.toJSON(httpRequest)), RequestUtils.class.getName());
            StringBuilder url = new StringBuilder(endpoint);
            url.append(httpRequest.getUrl());
            RequestBody requestBody = null;

            if (StringUtils.isNotBlank(httpRequest.getContentType())) {
                if (httpRequest.getParameterMap() != null && !httpRequest.getParameterMap().isEmpty()) {
                    FormBody.Builder builder = new FormBody.Builder();
                    for (Entry<String, String[]> param : httpRequest.getParameterMap().entrySet()) {
                        for (int i = 0; i < param.getValue().length; i++) {
                            builder.add(param.getKey(), param.getValue()[i]);
                        }
                    }
                    requestBody = builder.build();
                } else {
                    requestBody = RequestBody.create(httpRequest.getBody().toString(),
                            MediaType.parse(httpRequest.getContentType()));
                }
            } else if (StringUtils.equalsIgnoreCase(httpRequest.getMethod(), "POST")) {
                requestBody = RequestBody.create(httpRequest.getBody().toString(), null);
            }

            Builder requestBuilder = new Request.Builder();
            requestBuilder = requestBuilder.url(url.toString());

            if (HttpMethod.permitsRequestBody(httpRequest.getMethod())) {
                requestBuilder = requestBuilder.method(httpRequest.getMethod(), requestBody);
            } else {
                requestBuilder = requestBuilder.method(httpRequest.getMethod(), null);
            }
            requestBuilder = requestBuilder.headers(Headers.of((Map<String, String>) httpRequest.getHeaders()));

            return requestBuilder.build();
        } catch (Exception e){
            logger.log(LogLevel.FINEST, String.format(ERROR_IN_FUZZ_REQUEST_GENERATION, e.toString()), RequestUtils.class.getSimpleName());
        }
        return null;
    }
    public static String extractNRCsecFuzzReqHeader(FuzzRequestBean httpRequest) {
        if( httpRequest == null) {
            return null;
        }
        try {
            for (Map.Entry<String, String> header : httpRequest.getHeaders().entrySet()) {
                String key = header.getKey().toLowerCase();
                if (ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID.equals(key)){
                    return header.getValue();
                }
            }
        } catch (Exception e){
            return null;
        }
        return null;
    }
    public static String extractNRCsecFuzzReqHeader(Headers headers) {
        if (headers == null){
            return null;
        }
        try{
            for (Map.Entry<String, List<String>> header : headers.toMultimap().entrySet()) {
                String key = header.getKey().toLowerCase();
                if (ServletHelper.CSEC_IAST_FUZZ_REQUEST_ID.equals(key)){
                    return com.newrelic.api.agent.security.schema.StringUtils.join(header.getValue().toArray(new String[0]));
                }
            }
        } catch (Exception e){
            return null;
        }
        return null;
    }
}
