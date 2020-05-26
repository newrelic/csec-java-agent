package com.k2cybersecurity.instrumentator.httpclient;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.javaagent.FuzzFailEvent;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.k2cybersecurity.intcodeagent.websocket.WSClient;
import org.apache.commons.compress.utils.IOUtils;

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
		logger.log(LogLevel.INFO, String.format("Firing request :: Method : %s", request.method()), AsyncRestClient.class.getName());
		logger.log(LogLevel.INFO, String.format("Firing request :: URL : %s", request.url()), AsyncRestClient.class.getName());
		logger.log(LogLevel.INFO, String.format("Firing request :: Headers : %s", request.headers()), AsyncRestClient.class.getName());

		Call call = client.newCall(request);
		call.enqueue(new Callback() {
			@Override
			public void onFailure(Request request, IOException e) {
				// TODO Auto-generated method stub
				logger.log(LogLevel.INFO, String.format("Call failed : request %s reason : ", request), e, AsyncRestClient.class.getName());
				FuzzFailEvent fuzzFailEvent = new FuzzFailEvent();
				fuzzFailEvent.setFuzzHeader(request.header(IAgentConstants.K2_FUZZ_REQUEST_ID));
				EventSendPool.getInstance().sendEvent(fuzzFailEvent.toString());
			}

			@Override
			public void onResponse(Response response) throws IOException {
				// TODO Auto-generated method stub
				logger.log(LogLevel.INFO, String.format("Request success : %s :: response : %s", request, response), AsyncRestClient.class.getName());
				response.body().close();
//				if(response.code() % 100 == 4 || response.code() % 100 == 5){
//					FuzzFailEvent fuzzFailEvent = new FuzzFailEvent();
//					fuzzFailEvent.setFuzzHeader(request.header(K2_FUZZ_REQUEST_ID));
//					EventSendPool.getInstance().sendEvent(fuzzFailEvent.toString());
//				}
			}
		});
	}

}
