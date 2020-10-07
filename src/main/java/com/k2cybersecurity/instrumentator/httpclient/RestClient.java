package com.k2cybersecurity.instrumentator.httpclient;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.javaagent.FuzzFailEvent;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.squareup.okhttp.*;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

public class RestClient {


    public static final String REQUEST_SUCCESS_S_RESPONSE_S_S = "Request success : %s :: response : %s : %s";
    public static final String CALL_FAILED_REQUEST_S_REASON = "Call failed : request %s reason : ";
    public static final String FIRING_REQUEST_METHOD_S = "Firing request :: Method : %s";
    public static final String FIRING_REQUEST_URL_S = "Firing request :: URL : %s";
    public static final String FIRING_REQUEST_HEADERS_S = "Firing request :: Headers : %s";
    private final OkHttpClient client = new OkHttpClient();

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static RestClient instance;

    private RestClient() {
        ConnectionPool connectionPool = new ConnectionPool(1, 5, TimeUnit.MINUTES);
        client.setConnectionPool(connectionPool);
    }

    public static RestClient getInstance() {
        if (instance == null) {
            instance = new RestClient();
        }
        return instance;
    }

    public OkHttpClient getClient() {
        return client;
    }

    public void fireRequestAsync(Request request) {
        logger.log(LogLevel.INFO, String.format(FIRING_REQUEST_METHOD_S, request.method()), RestClient.class.getName());
        logger.log(LogLevel.INFO, String.format(FIRING_REQUEST_URL_S, request.url()), RestClient.class.getName());
        logger.log(LogLevel.INFO, String.format(FIRING_REQUEST_HEADERS_S, request.headers()), RestClient.class.getName());

        Call call = client.newCall(request);
        call.enqueue(new Callback() {
            @Override
            public void onFailure(Request request, IOException e) {
                // TODO Auto-generated method stub
                logger.log(LogLevel.INFO, String.format(CALL_FAILED_REQUEST_S_REASON, request), e, RestClient.class.getName());
                FuzzFailEvent fuzzFailEvent = new FuzzFailEvent();
                fuzzFailEvent.setFuzzHeader(request.header(IAgentConstants.K2_FUZZ_REQUEST_ID));
                EventSendPool.getInstance().sendEvent(fuzzFailEvent.toString());
            }

            @Override
            public void onResponse(Response response) throws IOException {
                // TODO Auto-generated method stub
                logger.log(LogLevel.INFO, String.format(REQUEST_SUCCESS_S_RESPONSE_S_S, request, response, response.body().string()), RestClient.class.getName());
                response.body().close();
                client.getConnectionPool().evictAll();

//				if(response.code() % 100 == 4 || response.code() % 100 == 5){
//					FuzzFailEvent fuzzFailEvent = new FuzzFailEvent();
//					fuzzFailEvent.setFuzzHeader(request.header(K2_FUZZ_REQUEST_ID));
//					EventSendPool.getInstance().sendEvent(fuzzFailEvent.toString());
//				}
            }
        });
    }

    public void fireRequest(Request request) {
        logger.log(LogLevel.INFO, String.format(FIRING_REQUEST_METHOD_S, request.method()), RestClient.class.getName());
        logger.log(LogLevel.INFO, String.format(FIRING_REQUEST_URL_S, request.url()), RestClient.class.getName());
        logger.log(LogLevel.INFO, String.format(FIRING_REQUEST_HEADERS_S, request.headers()), RestClient.class.getName());

        Call call = client.newCall(request);
        try {
            Response response = call.execute();
            logger.log(LogLevel.INFO, String.format(REQUEST_SUCCESS_S_RESPONSE_S_S, request, response, response.body().string()), RestClient.class.getName());
            response.body().close();
            client.getConnectionPool().evictAll();
        } catch (IOException e) {
            logger.log(LogLevel.INFO, String.format(CALL_FAILED_REQUEST_S_REASON, request), e, RestClient.class.getName());
            FuzzFailEvent fuzzFailEvent = new FuzzFailEvent();
            fuzzFailEvent.setFuzzHeader(request.header(IAgentConstants.K2_FUZZ_REQUEST_ID));
            EventSendPool.getInstance().sendEvent(fuzzFailEvent.toString());
        }


    }

}
