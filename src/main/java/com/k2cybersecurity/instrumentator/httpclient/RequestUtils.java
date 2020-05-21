package com.k2cybersecurity.instrumentator.httpclient;

import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.squareup.okhttp.FormEncodingBuilder;
import com.squareup.okhttp.Headers;
import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Request.Builder;
import com.squareup.okhttp.RequestBody;

public class RequestUtils {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	public static Request generateK2Request(HttpRequestBean httpRequestBean, String eventId) {

		StringBuilder url = new StringBuilder(String.format("%s://localhost", httpRequestBean.getProtocol()));
		url.append(":");
		url.append(httpRequestBean.getServerPort());
		url.append(httpRequestBean.getUrl());

		RequestBody requestBody = null;

		if (httpRequestBean.getParameterMap() != null) {
			FormEncodingBuilder builder = new FormEncodingBuilder();
			for (Entry<String, String[]> param : httpRequestBean.getParameterMap().entrySet()) {
				for (int i = 0; i < param.getValue().length; i++) {
					builder.add(param.getKey(), param.getValue()[i]);
				}
			}
			requestBody = builder.build();
		}
		else if (StringUtils.isNotBlank(httpRequestBean.getContentType())) {
			requestBody = RequestBody.create(MediaType.parse(httpRequestBean.getContentType()),
					httpRequestBean.getBody());
		}

		Builder requestBuilder = new Request.Builder();
		requestBuilder = requestBuilder.url(url.toString());
		requestBuilder = requestBuilder.method(httpRequestBean.getMethod(), requestBody);
		requestBuilder = requestBuilder.headers(Headers.of((Map<String, String>) httpRequestBean.getHeaders()));
		requestBuilder = requestBuilder.header("K2-Fuzz-Request-Id", eventId);

		return requestBuilder.build();
	}

}
