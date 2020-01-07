package com.k2cybersecurity.instrumentator.utils;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.unbescape.html.HtmlEscape;

import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.FileIntegrityBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.JADatabaseMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;

public class CallbackUtils {

	private static final Pattern htmlStartTagExtractor;

	private static final Pattern htmlArgExtractor;

	private static final Pattern functionCallDetector;

	private static Map<Integer, JADatabaseMetaData> sqlConnectionMap;
	
	static {
		htmlStartTagExtractor = Pattern.compile("(?:<script.*?>(.*?)<(?:\\/|\\\\\\/)script.*?>|<([!?a-zA-Z]+[0-9]*)(.*?)(?<!(\\\\))\\s*?>)",Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
		htmlArgExtractor = Pattern.compile("([\\s\\/]+[a-zA-z\\-\\_0-9]+[\\s\\/]*)=(('|\")(.*?)\\3|\\S+)", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
		functionCallDetector = Pattern
				.compile("([a-zA-Z0-9_-]+(?=(\\(.*?\\))))", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
		sqlConnectionMap = new LinkedHashMap<Integer, JADatabaseMetaData>(50) {
			@Override
			protected boolean removeEldestEntry(java.util.Map.Entry<Integer, JADatabaseMetaData> eldest) {
				return size() > 50;
			}
		};
	}

	public static void checkForFileIntegrity(Map<String, FileIntegrityBean> fileLocalMap) {
		for (Entry<String, FileIntegrityBean> entry : fileLocalMap.entrySet()) {
			boolean isExists = new File(entry.getKey()).exists();
			if (!entry.getValue().getExists().equals(isExists)) {
				EventDispatcher.dispatch(entry.getValue(), VulnerabilityCaseType.FILE_INTEGRITY);
			}
		}
	}

	public static boolean checkForReflectedXSS(HttpRequestBean httpRequestBean){
		AtomicBoolean isAttack = new AtomicBoolean(false);
		String responseBody = httpRequestBean.getResponseBody();

		HttpRequestBean requestBean = new HttpRequestBean(httpRequestBean);
		requestBean.setResponseBody(StringUtils.EMPTY);


		List<String> attackContructs = isXSS(requestBean.toString(), requestBean.getUrl());

		for (String construct : attackContructs) {
			if (StringUtils.containsIgnoreCase(responseBody, construct)) {
				System.err.println(String.format("Reflected XSS attack detected :: Construct : %s :: Request : %s :: Response : %s", construct, httpRequestBean, responseBody));
				isAttack.set(true);
				break;
			}
		}

		return isAttack.get();
	}
	/**
	 * Method to url decode given encodedString under UTF-8 encoding. If the
	 * conversion is not possible, <code>original string</code> is returned.
	 *
	 * @param encodedString URL encoded string
	 * @return URL decoded string
	 */
	public static String urlDecode(String encodedString) {
		String decodedString = StringUtils.EMPTY;
		try {
			decodedString = URLDecoder.decode(encodedString, StandardCharsets.UTF_8.name());
		} catch (Exception e) {
			decodedString = encodedString;
		}
		return decodedString;
	}


	/**
	 * Method to url decode given encodedString under UTF-8 encoding. If the
	 * conversion is not possible, <code>original string</code> is returned.
	 *
	 * @param encodedString URL encoded string
	 * @return URL decoded string
	 */
	public static String uriDecode(String encodedString) {
		String decodedString = StringUtils.EMPTY;
		try {
			decodedString = new URI(encodedString).getPath();
		} catch (Exception e) {
			decodedString = encodedString;
		}
		return decodedString;
	}

	private static List<String> isXSS(String rawRequest, String queryString) {
		List<String> attackConstructs = new ArrayList<>();
		String decodedRequest = urlDecode(urlDecode(rawRequest));
		String unEscapedHTML = HtmlEscape.unescapeHtml(decodedRequest);

		StringBuilder combinedData = new StringBuilder(decodedRequest);
		queryString = urlDecode(queryString);
		if (queryString != null)
			combinedData.append(queryString);
		combinedData.append(unEscapedHTML);

		Matcher htmlStartTagMatcher = htmlStartTagExtractor.matcher(combinedData);
		while (htmlStartTagMatcher.find()) {
			if(StringUtils.isNotBlank(htmlStartTagMatcher.group(1))){
				attackConstructs.add(htmlStartTagMatcher.group(1));
			} else if(StringUtils.isNotBlank(htmlStartTagMatcher.group(3))){
				String attribData = htmlStartTagMatcher.group(3);
				if (StringUtils.isNotBlank(attribData)) {
					Matcher attribMatcher = htmlArgExtractor.matcher(attribData);
					while (attribMatcher.find()) {
						String attribKey = attribMatcher.group(1);
						attribKey = StringUtils.trim(attribKey);
						attribKey = StringUtils.removeStart(attribKey, "/");
						attribKey = StringUtils.trim(attribKey);
						String attribVal;
						if (StringUtils.isNotBlank(attribMatcher.group(4))) {
							attribVal = attribMatcher.group(4);
						} else {
							attribVal = attribMatcher.group(2);
						}
						attribVal = StringUtils.removeEnd(attribVal, ">");

						// If js attrib used, mark PA if any function call is present inside.
						if (StringUtils.isNotBlank(attribKey)) {
							if (StringUtils.startsWithIgnoreCase(attribKey, "on") && StringUtils.isNotBlank(attribVal)) {
								Matcher functionCallMatcher = functionCallDetector.matcher(attribVal);
								if (functionCallMatcher.find()) {
									attackConstructs.add(attribMatcher.group());
									break;
								}
								// If other attrib is used for javascript injection
							} else if (StringUtils.isNotBlank(attribVal)) {
								if (StringUtils.containsIgnoreCase(attribVal, "javascript:") || StringUtils
										.endsWithIgnoreCase(attribVal, ".js") || StringUtils
										.startsWithIgnoreCase(attribVal, "http://") || StringUtils
										.startsWithIgnoreCase(attribVal, "https://")) {
									attackConstructs.add(attribMatcher.group());
								}
							}
						}

					}
				}
			}
		}

		return attackConstructs;
	}
	/**
	 * @return the sqlConnectionMap
	 */
	public static Map<Integer, JADatabaseMetaData> getSqlConnectionMap() {
		return sqlConnectionMap;
	}

	public static String getConnectionInformation(Object ref) {
		try {
			Method getConnection = ref.getClass().getMethod("getConnection", null);
			getConnection.setAccessible(true);
			Connection connection = (Connection) getConnection.invoke(ref, null);
			if (sqlConnectionMap.containsKey(connection.hashCode())) {
				JADatabaseMetaData metaData = sqlConnectionMap.get(connection.hashCode());
				return metaData.getDbName();
			} else {
				DatabaseMetaData dbMetaData = connection.getMetaData();
				sqlConnectionMap.put(connection.hashCode(), new JADatabaseMetaData(dbMetaData.getDatabaseProductName()));
				return dbMetaData.getDatabaseProductName();
			}
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "UNKNOWN";
	}

}
