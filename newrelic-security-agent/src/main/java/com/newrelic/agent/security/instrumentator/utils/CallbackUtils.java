package com.newrelic.agent.security.instrumentator.utils;

import com.newrelic.agent.security.instrumentator.K2Instrumentator;

import com.newrelic.agent.security.instrumentator.custom.*;
import com.newrelic.agent.security.instrumentator.dispatcher.EventDispatcher;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;

import com.newrelic.agent.security.intcodeagent.models.javaagent.*;
import org.apache.commons.lang3.RegExUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.unbescape.html.HtmlEscape;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CallbackUtils {

    private static final String HTML_COMMENT_END = "-->";
    private static final String HTML_COMMENT_START = "!--";
    public static final String C = "%3c";
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String BACKWARD_SLASH = "/";
    public static final String ANGLE_END = ">";
    public static final String ON = "on";
    public static final String JAVASCRIPT = "javascript:";
    public static final String JS = ".js";
    public static final String HTTP = "http://";
    public static final String HTTPS = "https://";
    public static final String GET_CONNECTION = "getConnection";
    public static final String GET_META_DATA = "getMetaData";
    public static final String GET_DATABASE_PRODUCT_NAME = "getDatabaseProductName";
    public static final String GET_DRIVER_NAME = "getDriverName";
    public static final String GET_DRIVER_VERSION = "getDriverVersion";
    public static final String ERROR = "Error :";
    public static final String UNKNOWN = "UNKNOWN";
    public static final String MY_SQL = "MySQL";
    public static final String MYSQL = "MYSQL";
    public static final String ORACLE = "ORACLE";
    public static final String DERBY = "DERBY";
    public static final String HSQL = "HSQL";
    public static final String SQLITE = "SQLITE";
    public static final String H_2 = "H2";
    public static final String MSSQL = "MSSQL";
    public static final String ENTERPRISEDB = "ENTERPRISEDB";
    public static final String PHOENIX = "PHOENIX";
    public static final String POSTGRESQL = "POSTGRESQL";
    public static final String DB_2 = "DB2";
    public static final String VERTICA = "VERTICA";
    public static final String SYBASE = "SYBASE";
    public static final String SAPANA = "SAPANA";
    public static final String GREENPLUM = "GREENPLUM";
    public static final String SOLIDDB = "SOLIDDB";
    public static final String MARIADB = "MARIADB";
    public static final String ORACLE1 = "Oracle";
    public static final String APACHE_DERBY = "Apache Derby";
    public static final String HSQL_DATABASE_ENGINE = "HSQL Database Engine";
    public static final String SQ_LITE = "SQLite";
    public static final String MICROSOFT_SQL_SERVER = "Microsoft SQL Server";
    public static final String ENTERPRISE_DB = "EnterpriseDB";
    public static final String PHOENIX1 = "Phoenix";
    public static final String POSTGRE_SQL = "PostgreSQL";
    public static final String VERTICA1 = "Vertica";
    public static final String ADAPTIVE = "Adaptive";
    public static final String ASE = "ASE";
    public static final String SQL_SERVER = "sql server";
    public static final String HDB = "HDB";
    public static final String GREENPLUM1 = "Greenplum";
    public static final String SOLID_DB = "solidDB";
    public static final String MARIA = "maria";
    public static final String FIVE_COLON = "::::";
    public static final String APPLICATION_JSON = "application/json";
    public static final String APPLICATION_XML = "application/xml";
    public static final String APPLICATION_X_WWW_FORM_URLENCODED = "application/x-www-form-urlencoded";
    public static final String SCRIPT = "script";
    public static final String SCRIPT_END = "</script";
    public static final String ON1 = "on";
    public static final String SRC = "src";
    public static final String HREF = "href";
    public static final Character ANGLE_END_CHAR = '>';
    public static final String ACTION = "action";
    public static final String EQUALS = "=";
    public static final String ANGLE_START = "<";
    public static final String ANGLE_START_URL_ENCODED_UPPERCASE = "%3C";
    public static final String FORMACTION = "formaction";
    public static final String SRCDOC = "srcdoc";
    public static final String DATA = "data";
    public static final String CAME_TO_XSS_CHECK = "Came to XSS check : ";
    private static final Pattern REGEX_SPACE = Pattern.compile("\\s+");

    public static Pattern tagNameRegex = Pattern.compile("<([a-zA-Z_\\-]+[0-9]*|!--)",
            Pattern.MULTILINE | Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    public static Pattern attribRegex = Pattern.compile(
            "([^(\\/\\s<'\">)]+?)(?:\\s*)=\\s*(('|\")([\\s\\S]*?)(?:(?=(\\\\?))\\5.)*?\\3|.+?(?=\\/>|>|\\?>|\\s|<\\/|$))",
            Pattern.MULTILINE | Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    public static Class requestInterface = null;
    public static Class responseInterface = null;

    public static void checkForFileIntegrity(Map<String, FileIntegrityBean> fileLocalMap)
            throws K2CyberSecurityException {
        for (Entry<String, FileIntegrityBean> entry : fileLocalMap.entrySet()) {
            boolean isExists = new File(entry.getKey()).exists();
            if (!entry.getValue().getExists().equals(isExists)) {
                EventDispatcher.dispatch(entry.getValue(), VulnerabilityCaseType.FILE_INTEGRITY, false);
            }
        }
    }

    // TODO: use complete response instead of just response body.
    public static Set<String> checkForReflectedXSS(HttpRequestBean httpRequestBean) {
        Set<String> toReturn = new HashSet<>();

        Set<String> combinedRequestData = decodeRequestData(httpRequestBean);
        if (combinedRequestData.isEmpty()) {
            toReturn.add(StringUtils.EMPTY);
            return toReturn;
        }
        Set<String> combinedResponseData = decodeResponseData(httpRequestBean.getHttpResponseBean());
        if (combinedResponseData.isEmpty()) {
            toReturn.add(StringUtils.EMPTY);
            return toReturn;
        }
//		System.out.println("Processed request data is : " + combinedRequestData);
//		 System.out.println("Processed response data is : " + combinedResponseData);
        String combinedResponseDataString = StringUtils.joinWith(FIVE_COLON, combinedResponseData);

        logger.log(LogLevel.DEBUG, String.format("Checking reflected XSS : %s :: %s", combinedRequestData, combinedResponseDataString), CallbackUtils.class.getName());

        Set<String> attackContructs = isXSS(combinedRequestData);

        for (String construct : attackContructs) {
            // System.err.println(String.format(
            // "Reflected XSS contruct detected :: %s :: Request : %s", construct,
            // httpRequestBean));
            if (StringUtils.containsIgnoreCase(combinedResponseDataString, construct)) {
                // System.err.println(String.format(
                // "Reflected XSS attack detected :: Construct : %s :: Request : %s :: Response
                // : %s", construct,
                // httpRequestBean, httpRequestBean.getHttpResponseBean().getResponseBody()));
                toReturn.add(construct);

                if (!(AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled()
                        && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled())) {
                    break;
                }
            }
        }
        if (toReturn.isEmpty()) {
            toReturn.add(StringUtils.EMPTY);
        }
        return toReturn;
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
        } catch (Throwable e) {
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
        } catch (Throwable e) {
            decodedString = encodedString;
        }
        return decodedString;
    }

    static Set<String> getXSSConstructs(String data) {
        logger.log(LogLevel.DEBUG, CAME_TO_XSS_CHECK + data, CallbackUtils.class.getName());
        List<String> construct = new ArrayList<>();
        boolean isAttackConstruct = false;

        // indicates the actual current position in the data where the processing ptr is.
        int currPos = 0;

        //
        int startPos = 0;

        //
        int tmpCurrPos = 0;

        //
        int tmpStartPos = 0;

        // iterate over the complete data string.
        while (currPos < data.length()) {
            Matcher matcher = tagNameRegex.matcher(data);
            if (!matcher.find(currPos)) {
                return new HashSet<>(construct);
            }
            isAttackConstruct = false;
            String tagName = matcher.group(1);
            if (StringUtils.isBlank(tagName)) {
                return new HashSet<>(construct);
            }
            startPos = matcher.start();
            currPos = matcher.end() - 1;
            if (StringUtils.equals(HTML_COMMENT_START, tagName)) {
                tmpCurrPos = StringUtils.indexOf(data, HTML_COMMENT_END, startPos);
                if (tmpCurrPos == -1) {
                    break;
                } else {
                    currPos = tmpCurrPos;
                    continue;
                }
            }
            tmpStartPos = tmpCurrPos = StringUtils.indexOf(data, ANGLE_END, startPos);

            if (tmpCurrPos == -1) {
                tmpStartPos = startPos;
            }

            Matcher attribMatcher = attribRegex.matcher(data);
            while (attribMatcher.find(currPos)) {
                String attribData = attribMatcher.group().trim();
                currPos = attribMatcher.end() - 1;
                tmpCurrPos = StringUtils.indexOf(data, ANGLE_END, tmpStartPos);

                if ((tmpCurrPos == -1 || attribMatcher.start() < tmpCurrPos)) {
                    tmpStartPos = tmpCurrPos = attribMatcher.end() - 1;
                    tmpStartPos++;
                    if (StringUtils.isBlank(attribMatcher.group(3)) && attribMatcher.end() >= tmpCurrPos) {
                        tmpStartPos = tmpCurrPos = StringUtils.indexOf(data, ANGLE_END, attribMatcher.start());
                        if (tmpStartPos == -1) {
                            tmpStartPos = data.length() - 1;
                        }
                        attribData = StringUtils.substring(attribData, 0, tmpStartPos);
                    }

                    String key = StringUtils.substringBefore(attribData, EQUALS);
                    String val = StringUtils.substringAfter(attribData, EQUALS);

                    if (StringUtils.isNotBlank(key) && (StringUtils.startsWithIgnoreCase(key, ON1)
                            || StringUtils.equalsIgnoreCase(key, SRC) || StringUtils.equalsIgnoreCase(key, HREF)
                            || StringUtils.equalsIgnoreCase(key, ACTION)
                            || StringUtils.equalsIgnoreCase(key, FORMACTION)
                            || StringUtils.equalsIgnoreCase(key, SRCDOC) || StringUtils.equalsIgnoreCase(key, DATA)
                            || StringUtils.containsIgnoreCase(
                            RegExUtils.removeAll(HtmlEscape.unescapeHtml(val), REGEX_SPACE), JAVASCRIPT))) {
                        isAttackConstruct = true;
                    }
                } else {
                    break;
                }
            }
            if (tmpCurrPos > 0) {
                currPos = tmpCurrPos;
            }
            if (data.charAt(currPos) != ANGLE_END_CHAR) {
                int tmp = StringUtils.indexOf(data, ANGLE_END, currPos);

                if (tmp != -1) {
                    currPos = tmp;
                } else if (!isAttackConstruct) {
                    continue;
                }
            }
            if (StringUtils.equalsIgnoreCase(tagName.trim(), SCRIPT)) {
                int locationOfEndTag = StringUtils.indexOfIgnoreCase(data, SCRIPT_END, currPos);
                if (locationOfEndTag != -1) {
                    String body = StringUtils.substring(data, currPos + 1, locationOfEndTag);
                    if (StringUtils.isNotBlank(body)) {
                        construct.add(StringUtils.substring(data, startPos, currPos + 1) + body);

                        continue;
                    }
                } else {
                    String body = StringUtils.substring(data, currPos + 1);
                    int tagEnd = StringUtils.indexOf(body, ANGLE_END);
                    if (StringUtils.isNotBlank(body) && tagEnd != -1) {
                        body = StringUtils.substring(body, tagEnd);
                        construct.add(StringUtils.substring(data, startPos, currPos + 1) + body);
                        break;
                    }
                }
            }

            if (isAttackConstruct) {
                construct.add(StringUtils.substring(data, startPos, currPos + 1));
            }
        }
        return new HashSet<>(construct);
    }

    public static Set<String> isXSS(Set<String> combinedData) {
        Set<String> attackConstructs = new HashSet<>();
        for (String data : combinedData) {
            attackConstructs.addAll(getXSSConstructs(data));
        }
        return attackConstructs;
    }


    public static String getConnectionInformation(Object ref, boolean needToGetConnection) {
        try {
            Object connection;
            if (needToGetConnection) {
                Method getConnection = ref.getClass().getMethod(GET_CONNECTION, null);
                getConnection.setAccessible(true);
                connection = getConnection.invoke(ref, null);
            } else {
                connection = ref;
            }
//			if (AgentUtils.getInstance().getSqlConnectionMap().containsKey(connection.hashCode())) {
//				JADatabaseMetaData metaData = AgentUtils.getInstance().getSqlConnectionMap().get(connection.hashCode());
//				return metaData.getDbIdentifier();
//			} else {
            Method getMetaData = connection.getClass().getMethod(GET_META_DATA, null);
            getMetaData.setAccessible(true);
            Object dbMetaData = getMetaData.invoke(connection, null);

            Method getDatabaseProductName = dbMetaData.getClass().getMethod(GET_DATABASE_PRODUCT_NAME, null);
            getDatabaseProductName.setAccessible(true);
            String productName = (String) getDatabaseProductName.invoke(dbMetaData, null);

//				Method getDriverName = dbMetaData.getClass().getMethod(GET_DRIVER_NAME, null);
//				getDriverName.setAccessible(true);
//				String driverName = (String) getDriverName.invoke(dbMetaData, null);
//
//				Method getDriverVersion = dbMetaData.getClass().getMethod(GET_DRIVER_VERSION, null);
//				getDriverVersion.setAccessible(true);
//				String driverVersion = (String) getDriverVersion.invoke(dbMetaData, null);

            if (StringUtils.isNotBlank(productName)) {
                JADatabaseMetaData jaDatabaseMetaData = new JADatabaseMetaData(productName);
//					jaDatabaseMetaData.setDriverName(driverName);
//					jaDatabaseMetaData.setDriverVersion(driverVersion);
                jaDatabaseMetaData.setDriverClassName(connection.getClass().getName());
                jaDatabaseMetaData.setDbIdentifier(detectDatabaseProduct(productName));
                // System.out.println("DB details detected: " + jaDatabaseMetaData);
//					AgentUtils.getInstance().getSqlConnectionMap().put(connection.hashCode(), jaDatabaseMetaData);
                return jaDatabaseMetaData.getDbIdentifier();
            }
//			}

        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, ERROR, e, CallbackUtils.class.getName());
        }
        return UNKNOWN;
    }

    private static String detectDatabaseProduct(String databaseProductName) {

        if (databaseProductName.contains(MY_SQL)) {
            return MYSQL;
        }
        if (databaseProductName.startsWith(ORACLE1)) {
            return ORACLE;
        }
        if (databaseProductName.startsWith(APACHE_DERBY)) {
            return DERBY;
        }
        if (databaseProductName.contains(HSQL_DATABASE_ENGINE)) {
            return HSQL;
        }
        if (databaseProductName.startsWith(SQ_LITE)) {
            return SQLITE;
        }
        if (databaseProductName.startsWith(H_2)) {
            return H_2;
        }
        if (databaseProductName.startsWith(MICROSOFT_SQL_SERVER)) {
            return MSSQL;
        }
        if (databaseProductName.startsWith(ENTERPRISE_DB)) {
            return ENTERPRISEDB;
        }
        if (databaseProductName.startsWith(PHOENIX1)) {
            return PHOENIX;
        }
        if (databaseProductName.startsWith(POSTGRE_SQL)) {
            return POSTGRESQL;
        }
        if (databaseProductName.startsWith(DB_2)) {
            return DB_2;
        }
        if (databaseProductName.startsWith(VERTICA1)) {
            return VERTICA;
        }
        if (databaseProductName.startsWith(ADAPTIVE) || databaseProductName.startsWith(ASE)
                || databaseProductName.startsWith(SQL_SERVER)) {
            return SYBASE;
        }
        if (databaseProductName.startsWith(HDB)) {
            return SAPANA;
        }
        if (databaseProductName.startsWith(GREENPLUM1)) {
            return GREENPLUM;
        }
        if (databaseProductName.contains(SOLID_DB)) {
            return SOLIDDB;
        }
        if (StringUtils.containsIgnoreCase(databaseProductName, MARIA)) {
            return MARIADB;
        }
        return UNKNOWN;
    }

    public static Set<String> decodeResponseData(HttpResponseBean httpResponseBean) {
        Set<String> processedData = new HashSet<>();
        String contentType = httpResponseBean.getResponseContentType();
        String responseBody = httpResponseBean.getResponseBody();
        String processedBody = responseBody;

//		String processedHeaders = StringEscapeUtils.unescapeJson(httpResponseBean.getHeaders().toString());
//		String oldHeaders = processedHeaders;

        try {
            processedData.add(processedBody);

            // processedBody = HtmlEscape.unescapeHtml(responseBody);
            // processedData.append(processedBody);
            // processedData.append(FIVE_COLON);

//			processedData.add(processedHeaders);

            // processedHeaders = HtmlEscape.unescapeHtml(processedHeaders);
            // processedData.append(processedHeaders);
            // processedData.append(FIVE_COLON);

//			processedBody = urlDecode(processedBody);
//			processedData.add(processedBody);

//			processedHeaders = urlDecode(processedHeaders);
//			processedData.add(processedHeaders);

            String oldProcessedBody;

            if (StringUtils.isNoneEmpty(responseBody)) {
                switch (contentType) {
                    case APPLICATION_JSON:
                        do {
                            oldProcessedBody = processedBody;
                            processedBody = StringEscapeUtils.unescapeJson(processedBody);
                            if (!StringUtils.equals(oldProcessedBody, processedBody)) {
                                processedData.add(processedBody);
                                // System.out.println("Decoding JSON: " + processedBody);
                            }
                        } while (!StringUtils.equals(oldProcessedBody, processedBody));
                        break;
                    case APPLICATION_XML:
                        do {
                            oldProcessedBody = processedBody;
                            processedBody = StringEscapeUtils.unescapeXml(processedBody);
                            if (!StringUtils.equals(oldProcessedBody, processedBody)) {
                                processedData.add(processedBody);
                                // System.out.println("Decoding XML: " + processedBody);
                            }
                        } while (!StringUtils.equals(oldProcessedBody, processedBody));
                        break;

                }
            }
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, ERROR, e, CallbackUtils.class.getName());
        }
        return processedData;
    }

    public static Set<String> decodeRequestData(HttpRequestBean httpRequestBean) {
        Set<String> processedData = new HashSet<>();
        String contentType = httpRequestBean.getContentType();
        String body = httpRequestBean.getBody();
        String processedBody = body;

        try {

            // Process & add header keys & values separately.
            Map<String, String> headerCopy = new HashMap<>((Map<String, String>) httpRequestBean.getHeaders());
            headerCopy.remove("k2-fuzz-request-id");
            for (Entry<String, String> entry : headerCopy.entrySet()) {
                // For key
                processURLEncodedDataForXSS(processedData, entry.getKey());

                // For Value
                processURLEncodedDataForXSS(processedData, entry.getValue());
            }

            // Process ParameterMap
            if (httpRequestBean.getParameterMap() != null) {
                for (Entry<String, String[]> entry : httpRequestBean.getParameterMap().entrySet()) {
                    if (StringUtils.contains(entry.getKey(), ANGLE_START)) {
                        processedData.add(entry.getKey());
                    }
                    for (String val : entry.getValue()) {
                        if (StringUtils.contains(val, ANGLE_START)) {
                            processedData.add(val);
                        }
                    }
                }
            }

            // For URL
            processURLEncodedDataForXSS(processedData, httpRequestBean.getUrl());


            if (StringUtils.isNotBlank(processedBody)) {
                // Process body
                processedData.add(processedBody);
                String oldProcessedBody;
                switch (contentType) {
                    case APPLICATION_JSON:
//					do {
                        oldProcessedBody = processedBody;
                        processedBody = StringEscapeUtils.unescapeJson(processedBody);
                        if (!StringUtils.equals(oldProcessedBody, processedBody)
                                && StringUtils.contains(processedBody, ANGLE_START)) {
                            processedData.add(processedBody);
                            // System.out.println("Decoding JSON: " + processedBody);
                        }
//					} while (!StringUtils.equals(oldProcessedBody, processedBody));
                        break;
                    case APPLICATION_XML:
//					do {
                        oldProcessedBody = processedBody;
                        processedBody = StringEscapeUtils.unescapeXml(processedBody);
                        if (!StringUtils.equals(oldProcessedBody, processedBody)
                                && StringUtils.contains(processedBody, ANGLE_START)) {
                            processedData.add(processedBody);
                            // System.out.println("Decoding XML: " + processedBody);
                        }
//					} while (!StringUtils.equals(oldProcessedBody, processedBody));
                        break;

                    case APPLICATION_X_WWW_FORM_URLENCODED:
                        processedBody = urlDecode(processedBody);
                        processedData.add(processedBody);

//					do {
                        oldProcessedBody = processedBody;
                        processedBody = urlDecode(processedBody);
                        if (!StringUtils.equals(oldProcessedBody, processedBody)
                                && StringUtils.contains(processedBody, ANGLE_START)) {
                            processedData.add(processedBody);
                            // System.out.println("Decoding URL: " + processedBody);
                        }
//					} while (!StringUtils.equals(oldProcessedBody, processedBody));

                        break;
                }

            }
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, ERROR, e, CallbackUtils.class.getName());
        }
        return processedData;
    }

//	private static void processURLEncodedDataForXSS(Set<String> processedData, String data) {
//		String key = data;
//		String oldKey = new String(key);
//
//		do {
//			if (StringUtils.contains(key, ANGLE_START)) {
//				processedData.add(key);
//			}
//			oldKey = key;
//			key = urlDecode(key);
//		} while (!StringUtils.equals(oldKey, key));
//	}

    private static void processURLEncodedDataForXSS(Set<String> processedData, String data) {
        String key = data;
        if (StringUtils.contains(key, ANGLE_START)) {
            processedData.add(key);
        }
        key = urlDecode(key);
        if (StringUtils.contains(key, ANGLE_START)) {
            processedData.add(key);
        }
    }

    public static boolean checkArgsTypeHeirarchy(Object requestArg, Object responseArg) {
        if (requestArg == null || responseArg == null) {
            return false;
        }
        try {
            if (requestInterface == null) {
                requestInterface = Class.forName("javax.servlet.http.HttpServletRequest", false,
                        requestArg.getClass().getClassLoader());
            }
            if (responseInterface == null) {
                responseInterface = Class.forName("javax.servlet.http.HttpServletResponse", false,
                        responseArg.getClass().getClassLoader());
            }
            return requestInterface.isAssignableFrom(requestArg.getClass())
                    && responseInterface.isAssignableFrom(responseArg.getClass());
        } catch (Throwable e) {
            // e.printStackTrace();
        }
        return false;
    }

    public static boolean checkArgsTypeHeirarchyRequest(Object requestArg) {
        if (requestArg == null) {
            return false;
        }
        try {
            if (requestInterface == null) {
                requestInterface = Class.forName("javax.servlet.http.HttpServletRequest", false,
                        requestArg.getClass().getClassLoader());
            }
            return requestInterface.isAssignableFrom(requestArg.getClass());
        } catch (Throwable e) {
            // e.printStackTrace();
        }
        return false;
    }

    public static boolean checkArgsTypeHeirarchyResponse(Object responseArg) {
        if (responseArg == null) {
            return false;
        }
        try {
            if (responseInterface == null) {
                responseInterface = Class.forName("javax.servlet.http.HttpServletResponse", false,
                        responseArg.getClass().getClassLoader());
            }
            return responseInterface.isAssignableFrom(responseArg.getClass());
        } catch (Throwable e) {
            // e.printStackTrace();
        }
        return false;
    }

    public static void cleanUpAllStates() {
        // Clean up
        ThreadLocalHTTPServiceLock.getInstance().resetLock();
        ThreadLocalHttpMap.getInstance().cleanState();
        ThreadLocalDBMap.getInstance().clearAll();
        ThreadLocalSessionMap.getInstance().clearAll();
        ThreadLocalLDAPMap.getInstance().clearAll();
        ThreadLocalExecutionMap.getInstance().cleanUp();
        ThreadLocalLdaptiveMap.getInstance().clearAll();
        ThreadLocalXpathSaxonMap.getInstance().clearAll();
        ThreadLocalXQuerySaxonMap.getInstance().clearAll();
        ThreadLocalOkHttpMap.getInstance().clearAll();
        ThreadLocalSSRFLock.getInstance().resetLock();
        ThreadLocalJSRhinoMap.getInstance().clearAll();
    }

    public static String generateApiCallerHeaderValue(String targetURL) {
        return String.format("%s||%s||%s||%s",
                K2Instrumentator.APPLICATION_UUID,
                ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getContextPath(),
                ThreadLocalExecutionMap.getInstance().getHttpRequestBean().getServerPort(),
                Base64.getEncoder().encodeToString(targetURL.getBytes(StandardCharsets.UTF_8)));
    }

    public static String generateTracingHeaderValue(String previousValue, String apiId, String executionId) {

        if (StringUtils.isNotBlank(previousValue)) {
            previousValue = StringUtils.appendIfMissing(previousValue, ";");
        }
        return String.format("%s%s/%s/%s;", previousValue, K2Instrumentator.APPLICATION_UUID, apiId, executionId);

//        StringBuilder value = new StringBuilder(previousValue);
//        if((AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getEnabled() && AgentUtils.getInstance().getAgentPolicy().getVulnerabilityScan().getIastScan().getEnabled())){
//            value.append(K2Instrumentator.APPLICATION_UUID);
//            value.append(':');
//        }
//        value.append(apiId);
//        value.append(';');
//        return value.toString();
    }
}