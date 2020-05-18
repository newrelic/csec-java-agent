package com.k2cybersecurity.instrumentator.httpclient;

import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.squareup.okhttp.Headers;
import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Request.Builder;
import com.squareup.okhttp.RequestBody;

public class RequestUtils {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	public static Request generateK2Request(HttpRequestBean httpRequestBean, String eventId) {

		StringBuilder url = new StringBuilder("localhost");
		url.append(":");
		url.append(httpRequestBean.getServerPort());
		url.append(httpRequestBean.getUrl());

		RequestBody requestBody = null;
		
		if(StringUtils.isNotBlank(httpRequestBean.getContentType())) {
			requestBody = RequestBody.create(MediaType.parse(httpRequestBean.getContentType()),
					httpRequestBean.getBody());
		}
		
		Builder requestBuilder = new Request.Builder();
		requestBuilder = requestBuilder.url(url.toString());
		requestBuilder = requestBuilder.method(httpRequestBean.getMethod(), requestBody);
		requestBuilder = requestBuilder.headers(Headers.of((Map<String, String>) httpRequestBean.getHeaders()));
		requestBuilder = requestBuilder.addHeader("K2-Fuzz-Request-Id", eventId);

		return requestBuilder.build();
	}

}
