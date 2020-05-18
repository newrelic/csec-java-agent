package com.k2cybersecurity.instrumentator.httpclient;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.squareup.okhttp.Call;
import com.squareup.okhttp.Callback;
import com.squareup.okhttp.ConnectionPool;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;

public class AsyncRestClient {

	private static OkHttpClient client;
	
	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	public static AsyncRestClient instance;

	private AsyncRestClient() {
		ConnectionPool connectionPool = new ConnectionPool(5, 5, TimeUnit.MINUTES);
		client = new OkHttpClient();
		client.setConnectionPool(connectionPool);
	}

	public static AsyncRestClient getInstance() {
		if (instance == null) {
			instance = new AsyncRestClient();
		}
		return instance;
	}

	public static OkHttpClient getClient() {
		return client;
	}

	public void fireRequest(Request request) {
		Call call = client.newCall(request);
		call.enqueue(new Callback() {
			@Override
			public void onFailure(Request request, IOException e) {
				// TODO Auto-generated method stub
				logger.log(LogLevel.INFO, String.format("Call failed : request %s reason : ", request), e, AsyncRestClient.class.getName());
			}

			@Override
			public void onResponse(Response response) throws IOException {
				// TODO Auto-generated method stub
				logger.log(LogLevel.INFO, String.format("Request success : %s :: response : %s", request, response), AsyncRestClient.class.getName());
			}
		});
	}

}
