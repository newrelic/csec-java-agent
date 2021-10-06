package com.k2cybersecurity.instrumentator.httpclient;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.javaagent.FuzzFailEvent;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.squareup.okhttp.*;
import org.apache.commons.io.FileUtils;

import javax.net.ssl.*;
import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeUnit;

public class RestClient {


    public static final String REQUEST_SUCCESS_S_RESPONSE_S_S = "Request success : %s :: response : %s : %s";
    public static final String CALL_FAILED_REQUEST_S_REASON = "Call failed : request %s reason : ";
    public static final String FIRING_REQUEST_METHOD_S = "Firing request :: Method : %s";
    public static final String FIRING_REQUEST_URL_S = "Firing request :: URL : %s";
    public static final String FIRING_REQUEST_HEADERS_S = "Firing request :: Headers : %s";
    private final ThreadLocal<OkHttpClient> clientThreadLocal = new ThreadLocal<OkHttpClient>() {
        @Override
        protected OkHttpClient initialValue() {
            OkHttpClient client = new OkHttpClient();
            return clientInit(client);
        }
    };
//    private final OkHttpClient client = new OkHttpClient();

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    public static RestClient instance;

    private static final Object lock = new Object();

    // Create a trust manager that does not validate certificate chains
    private final TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                }

                @Override
                public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                }

                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return new java.security.cert.X509Certificate[]{};
                }
            }
    };

    private RestClient() {
        //            // TODO: Add handling for Windows platform
        FileUtils.deleteQuietly(new File(File.separator + "tmp" + File.separator + "k2-ic" + File.separator + "ds-tmp"));
    }

    private OkHttpClient clientInit(OkHttpClient client) {
        ConnectionPool connectionPool = new ConnectionPool(1, 5, TimeUnit.MINUTES);
        client.setConnectionPool(connectionPool);

        try {
            // Install the all-trusting trust manager
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            // Create an ssl socket factory with our all-trusting manager
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            client.setSslSocketFactory(sslSocketFactory);
            client.setHostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return client;
    }

    public static RestClient getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new RestClient();
                }
            }
        }
        return instance;
    }

    public OkHttpClient getClient() {
        return clientThreadLocal.get();
    }

    public void fireRequestAsync(Request request) {
        OkHttpClient client = clientThreadLocal.get();
        logger.log(LogLevel.DEBUG, String.format(FIRING_REQUEST_METHOD_S, request.method()), RestClient.class.getName());
        logger.log(LogLevel.DEBUG, String.format(FIRING_REQUEST_URL_S, request.url()), RestClient.class.getName());
        logger.log(LogLevel.DEBUG, String.format(FIRING_REQUEST_HEADERS_S, request.headers()), RestClient.class.getName());

        Call call = client.newCall(request);
        call.enqueue(new Callback() {
            @Override
            public void onFailure(Request request, IOException e) {
                // TODO Auto-generated method stub
                logger.log(LogLevel.DEBUG, String.format(CALL_FAILED_REQUEST_S_REASON, request), e, RestClient.class.getName());
                FuzzFailEvent fuzzFailEvent = new FuzzFailEvent(K2Instrumentator.APPLICATION_UUID);
                fuzzFailEvent.setFuzzHeader(request.header(IAgentConstants.K2_FUZZ_REQUEST_ID));
                EventSendPool.getInstance().sendEvent(fuzzFailEvent.toString());
            }

            @Override
            public void onResponse(Response response) throws IOException {
                // TODO Auto-generated method stub
                logger.log(LogLevel.DEBUG, String.format(REQUEST_SUCCESS_S_RESPONSE_S_S, request, response, response.body().string()), RestClient.class.getName());
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
        OkHttpClient client = clientThreadLocal.get();

        logger.log(LogLevel.DEBUG, String.format(FIRING_REQUEST_METHOD_S, request.method()), RestClient.class.getName());
        logger.log(LogLevel.DEBUG, String.format(FIRING_REQUEST_URL_S, request.url()), RestClient.class.getName());
        logger.log(LogLevel.DEBUG, String.format(FIRING_REQUEST_HEADERS_S, request.headers()), RestClient.class.getName());

        Call call = client.newCall(request);
        try {
            Response response = call.execute();
            logger.log(LogLevel.DEBUG, String.format(REQUEST_SUCCESS_S_RESPONSE_S_S, request, response, response.body().string()), RestClient.class.getName());
            response.body().close();
            if (client.getConnectionPool() != null) {
                client.getConnectionPool().evictAll();
            }
        } catch (IOException e) {
            logger.log(LogLevel.DEBUG, String.format(CALL_FAILED_REQUEST_S_REASON, request), e, RestClient.class.getName());
            FuzzFailEvent fuzzFailEvent = new FuzzFailEvent(K2Instrumentator.APPLICATION_UUID);
            fuzzFailEvent.setFuzzHeader(request.header(IAgentConstants.K2_FUZZ_REQUEST_ID));
            EventSendPool.getInstance().sendEvent(fuzzFailEvent.toString());
        }


    }

}
