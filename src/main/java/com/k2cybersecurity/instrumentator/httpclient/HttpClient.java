package com.k2cybersecurity.instrumentator.httpclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.k2cybersecurity.instrumentator.os.OSVariables;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.instrumentator.utils.CollectorConfigurationUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.squareup.okhttp.*;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import javax.net.ssl.*;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.k2cybersecurity.instrumentator.httpclient.IRestClientConstants.COLLECTOR_UPLOAD_LOG;

class LoggingInterceptor implements Interceptor {
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String SENDING_REQUEST_S_ON_S_N_S = "Sending request %s";
    public static final String RECEIVED_RESPONSE_FOR_S_IN_1_FMS_N_S = "Received response is %s for %s in %.1fms%n";

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

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String APPLICATION_JSON = "application/json";
    public static final String UNKNOWN_ASYNC_API_S = "unknown async API: %s";
    public static final String K_2_API_ACCESSOR_TOKEN = "K2_API_ACCESSOR_TOKEN";
    public static final String K_2_CUSTOMER_ID = "K2_CUSTOMER_ID";
    public static final String SSL = "SSL";

    private static HttpClient instance;

    private static final Object lock = new Object();

    private OkHttpClient client;

    private String baseUrl;

    private ObjectMapper objectMapper = new ObjectMapper();

    private OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

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

    private HttpClient() {
        ConnectionPool pool = new ConnectionPool(1, TimeUnit.MINUTES.toMillis(10));
        client = new OkHttpClient();
        client.setConnectionPool(pool);
        client.interceptors().add(new LoggingInterceptor());

        // Install the all-trusting trust manager
        try {
            final SSLContext sslContext;
            sslContext = SSLContext.getInstance(SSL);
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
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            logger.log(LogLevel.ERROR, e.getMessage(), e, HttpClient.class.getName());
        }

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
        builder.add(K_2_CUSTOMER_ID, String.valueOf(CollectorConfigurationUtils.getInstance().getCollectorConfig().getCustomerInfo().getCustomerId()));
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

        RequestBody requestBody = new MultipartBuilder().type(MultipartBuilder.FORM)
                .addFormDataPart("file", fileToUpload.getName(), RequestBody.create(MediaType.parse("multipart/form-data"), fileToUpload))
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

        RequestBody requestBody = RequestBody.create(MediaType.parse(APPLICATION_JSON), body.toString());

        Headers httpHeaders = getHeaders(headers);

        Request request = new Request.Builder()
                .post(requestBody)
                .headers(httpHeaders)
                .url(httpUrl.toString())
                .build();
        return fire(request, isAsync, url, null);
    }

    private HttpUrl buildUrl(String url, List<String> pathParams, Map<String, String> queryParams) {
        logger.log(LogLevel.INFO, String.format("url : %s  path param : %s  query params : %s", url, pathParams, queryParams), HttpClient.class.getName());
        url = String.format(url, pathParams);
        url = StringUtils.join(baseUrl, url);
        logger.log(LogLevel.INFO, String.format("updated url : %s ", url), HttpClient.class.getName());
        HttpUrl.Builder builder = HttpUrl.parse(url).newBuilder();
        if (queryParams != null) {
            for (String paramName : queryParams.keySet()) {
                builder.addQueryParameter(paramName, queryParams.get(paramName));
            }
        }
        return builder.build();
    }

    private Response fire(Request request, Boolean isAsync, String api, File file) {
        Call call = client.newCall(request);
        if (isAsync) {
            switch (api) {
                case COLLECTOR_UPLOAD_LOG:
                    fileUploadAndDelete(call, api, file);
                default:
                    logger.log(LogLevel.WARNING, String.format(UNKNOWN_ASYNC_API_S, api), HttpClient.class.getName());
            }
            return new Response.Builder().code(200).build();
        }
        try {
            return call.execute();
        } catch (IOException e) {
            logger.log(LogLevel.ERROR, e.getMessage(), e, HttpClient.class.getName());
        }
        return new Response.Builder().code(400).build();
    }

    private void fileUploadAndDelete(Call request, String api, File file) {
        request.enqueue(new Callback() {
            @Override
            public void onFailure(Request request, IOException e) {
                logger.log(LogLevel.ERROR, String.format("API %s failed!", api), e, HttpClient.class.getName());
            }

            @Override
            public void onResponse(Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful()) {
                        logger.log(LogLevel.ERROR, String.format("API %s failed! code : %s : %s ", api, response.code(), responseBody), HttpClient.class.getName());
                        FileUtils.deleteQuietly(file);
                    }
                    logger.log(LogLevel.INFO, String.format("API %s returns success! code : %s : %s ", api, response.code(), responseBody), HttpClient.class.getName());
                }
            }
        });
    }

    public <T> T readResponse(InputStream stream, java.lang.Class<T> valueType) {
        try {
            return objectMapper.readValue(stream, valueType);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
