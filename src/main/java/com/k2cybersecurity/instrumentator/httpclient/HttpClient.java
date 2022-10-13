package com.k2cybersecurity.instrumentator.httpclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.k2cybersecurity.instrumentator.os.OSVariables;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.instrumentator.utils.CollectorConfigurationUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import okhttp3.*;
import okhttp3.OkHttpClient.Builder;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import javax.net.ssl.*;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.k2cybersecurity.instrumentator.httpclient.IRestClientConstants.COLLECTOR_UPLOAD_LOG;

class LoggingInterceptor implements Interceptor {
    public static final String SENDING_REQUEST_S_ON_S_N_S = "Sending request %s";
    public static final String RECEIVED_RESPONSE_FOR_S_IN_1_FMS_N_S = "Received response is %s for %s in %.1fms%n";
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    @Override
    public Response intercept(Interceptor.Chain chain) throws IOException {
        Request request = chain.request();

        long t1 = System.nanoTime();
        logger.log(LogLevel.INFO, String.format(SENDING_REQUEST_S_ON_S_N_S,
                request.url()), LoggingInterceptor.class.getName());

        Response response = chain.proceed(request);

        long t2 = System.nanoTime();
        logger.log(LogLevel.INFO, String.format(RECEIVED_RESPONSE_FOR_S_IN_1_FMS_N_S, response.code(),
                response.request().url(), (t2 - t1) / 1e6d), LoggingInterceptor.class.getName());

        return response;
    }
}

public class HttpClient {

    public static final String APPLICATION_JSON = "application/json";
    public static final String UNKNOWN_ASYNC_API_S = "unknown async API: %s";
    public static final String K_2_API_ACCESSOR_TOKEN = "K2_API_ACCESSOR_TOKEN";
    public static final String K_2_CUSTOMER_ID = "K2_CUSTOMER_ID";
    public static final String SSL = "SSL";
    public static final String API_S_FAILED = "API %s failed!";
    public static final String ASYNC_API_EXECUTION_FAILED_S = "Async API execution failed %s";
    public static final String ASYNC_API_EXECUTION_UNSUCCESSFULLY_S_RESPONSE_IS_S_BODY_S = "Async API execution unsuccessfully %s : response is %s :: body : %s";
    public static final String ASYNC_API_EXECUTED_SUCCESSFULLY_S_RESPONSE_IS_S = "Async API executed successfully %s : response is %s";
    public static final String API_S_FAILED_CODE_S_S = "API %s failed! code : %s : %s ";
    public static final String API_S_RETURNS_SUCCESS_CODE_S_S = "API %s returns success! code : %s : %s ";
    public static final String MULTIPART_FILE = "file";
    public static final String MULTIPART_FORM_DATA = "multipart/form-data";
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    private static final Object lock = new Object();
    public static final String READ_RESPONSE_FAILED = "Read response failed!!!";
    public static final String READ_RESPONSE_FAILED_MESSAGE_S_CAUSE_S = "Read response failed MESSAGE: %s  CAUSE: %s";
    public static final String NO_CONTENT = "No Content";
    private static HttpClient instance;
    // Create a trust manager that does not validate certificate chains
    private final X509TrustManager x509TrustManager = new X509TrustManager() {
        @Override
        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType)
                throws CertificateException {
        }

        @Override
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType)
                throws CertificateException {
        }

        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[] {};
        }
    };

    // Create a trust manager that does not validate certificate chains
    private final TrustManager[] trustAllCerts = new TrustManager[] {
            x509TrustManager
    };

    private OkHttpClient client;
    private String baseUrl;
    private ObjectMapper objectMapper = new ObjectMapper();
    private OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

    private HttpClient() {
        Builder builder = new OkHttpClient.Builder();
        try {
            ConnectionPool connectionPool = new ConnectionPool(1, 5, TimeUnit.MINUTES);
            builder = builder.connectionPool(connectionPool);

            // Install the all-trusting trust manager
            final SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            // Create an ssl socket factory with our all-trusting manager
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            builder = builder.sslSocketFactory(sslSocketFactory, x509TrustManager);

            builder.interceptors().add(new LoggingInterceptor());
            builder = builder.hostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        client = builder.build();

        baseUrl = CollectorConfigurationUtils.getInstance().getCollectorConfig().getK2ServiceInfo().getResourceServiceEndpointURL();
    }

    public void resetClientURL() {
        baseUrl = CollectorConfigurationUtils.getInstance().getCollectorConfig().getK2ServiceInfo().getResourceServiceEndpointURL();
    }

    public static HttpClient getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new HttpClient();
                }
            }
        }
        return instance;
    }

    private Headers getHeaders(Map<String, String> headers) {
        Headers.Builder builder = new Headers.Builder();
        builder.add(K_2_API_ACCESSOR_TOKEN, CollectorConfigurationUtils.getInstance().getCollectorConfig().getCustomerInfo().getApiAccessorToken());
        if (headers != null) {
            headers.forEach((key, value) -> {
                builder.add(key, value);
            });
        }
        return builder.build();
    }

    public Response doGet(String url, List<String> pathParams, Map<String, String> queryParams, Map<String, String> headers, Boolean isAsync) {
        HttpUrl httpUrl = buildUrl(url, pathParams, queryParams);

        Headers httpHeaders = getHeaders(headers);

        Request request = new Request.Builder()
                .get()
                .headers(httpHeaders)
                .url(httpUrl.toString())
                .build();
        return fire(request, isAsync, url, null);
    }

    public Response doPost(String url, List<String> pathParams, Map<String, String> queryParams, Map<String, String> headers, File fileToUpload) {
        HttpUrl httpUrl = buildUrl(url, pathParams, queryParams);

        RequestBody requestBody = new MultipartBody.Builder().setType(MultipartBody.FORM)
                .addFormDataPart(MULTIPART_FILE, fileToUpload.getName(), RequestBody.create(fileToUpload, MediaType
                        .parse(MULTIPART_FORM_DATA)))
                .build();

        Headers httpHeaders = getHeaders(headers);

        Request request = new Request.Builder()
                .post(requestBody)
                .headers(httpHeaders)
                .url(httpUrl.toString())
                .build();
        return fire(request, true, url, fileToUpload);
    }

    public Response doPost(String url, List<String> pathParams, Map<String, String> queryParams, Map<String, String> headers, Object body, Boolean isAsync) {
        HttpUrl httpUrl = buildUrl(url, pathParams, queryParams);

        RequestBody requestBody = RequestBody.create(body.toString(), MediaType.parse(APPLICATION_JSON));

        Headers httpHeaders = getHeaders(headers);

        Request request = new Request.Builder()
                .post(requestBody)
                .headers(httpHeaders)
                .url(httpUrl.toString())
                .build();
        return fire(request, isAsync, url, null);
    }

    private HttpUrl buildUrl(String url, List<String> pathParams, Map<String, String> queryParams) {
        url = String.format(url, pathParams);
        url = StringUtils.join(baseUrl, url);
        HttpUrl.Builder builder = HttpUrl.parse(url).newBuilder();
        if (queryParams != null) {
            for (String paramName : queryParams.keySet()) {
                builder.addQueryParameter(paramName, queryParams.get(paramName));
            }
        }
        return builder.build();
    }

    private Response fire(Request request, Boolean isAsync, String api, File file) {
        try {
            Call call = client.newCall(request);
            if (isAsync) {
                switch (api) {
                    case COLLECTOR_UPLOAD_LOG:
                        fileUploadAndDelete(call, api, file);
                        break;
                    default:
                        executeAsync(call, api);
                        break;
//                    logger.log(LogLevel.WARNING, String.format(UNKNOWN_ASYNC_API_S, api), HttpClient.class.getName());
                }
                return new Response.Builder().protocol(Protocol.HTTP_1_1).request(request).code(204).message(NO_CONTENT).build();
            }

            return call.execute();
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, e.getMessage(), e, HttpClient.class.getName());
        }
        return new Response.Builder().protocol(Protocol.HTTP_1_1).request(request).code(400).build();
    }

    private void executeAsync(Call call, String api) {
        call.enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                logger.log(LogLevel.ERROR, String.format(ASYNC_API_EXECUTION_FAILED_S, 
                        call.request().toString()), e, HttpClient.class.getName());
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if (!response.isSuccessful()) {
                    try (ResponseBody responseBody = response.body()) {
                        logger.log(LogLevel.WARN, String.format(ASYNC_API_EXECUTION_UNSUCCESSFULLY_S_RESPONSE_IS_S_BODY_S, api, response.code(), responseBody), HttpClient.class.getName());
                    }
                } else {
                    logger.log(LogLevel.INFO, String.format(ASYNC_API_EXECUTED_SUCCESSFULLY_S_RESPONSE_IS_S, api, response.code()), HttpClient.class.getName());
                }
            }
        });
    }

    private void fileUploadAndDelete(Call request, String api, File file) {
        request.enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                logger.log(LogLevel.ERROR, String.format(API_S_FAILED, api), e, HttpClient.class.getName());
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful()) {
                        logger.log(LogLevel.WARN, String.format(API_S_FAILED_CODE_S_S, api, response.code(), responseBody), HttpClient.class.getName());
                    } else {
                        FileUtils.deleteQuietly(file);
                        logger.log(LogLevel.INFO, String.format(API_S_RETURNS_SUCCESS_CODE_S_S, api, response.code(), responseBody), HttpClient.class.getName());
                    }
                }
            }
        });
    }

    public <T> T readResponse(InputStream stream, java.lang.Class<T> valueType) {
        try {
            return objectMapper.readValue(stream, valueType);
        } catch (IOException e) {
            logger.log(LogLevel.ERROR, String.format(READ_RESPONSE_FAILED_MESSAGE_S_CAUSE_S, e.getMessage(), e.getCause()), HttpClient.class.getName());
            logger.log(LogLevel.DEBUG, READ_RESPONSE_FAILED, e, HttpClient.class.getName());
        }
        return null;
    }
}
