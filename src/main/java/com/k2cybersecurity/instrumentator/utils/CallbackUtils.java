package com.k2cybersecurity.instrumentator.utils;

import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.models.javaagent.*;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.unbescape.html.HtmlEscape;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CallbackUtils {

    private static final Pattern htmlStartTagExtractor;

    private static final Pattern htmlArgExtractor;

    private static final Pattern functionCallDetector;

    private static Map<Integer, JADatabaseMetaData> sqlConnectionMap;

    static {
        htmlStartTagExtractor = Pattern.compile(
                "(?:<script.*?>(.*?)<(?:\\/|\\\\\\/)script.*?>|<([!?a-zA-Z]+[0-9]*)(.*?)(?<!(\\\\))\\s*?>)",
                Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
        htmlArgExtractor = Pattern.compile("([\\s\\/]+[a-zA-z\\-\\_0-9]+[\\s\\/]*)=(('|\")(.*?)\\3|\\S+)",
                Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
        functionCallDetector = Pattern.compile("([a-zA-Z0-9_-]+(?=(\\(.*?\\))))",
                Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
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

    // TODO: use complete response instead of just response body.
    public static String checkForReflectedXSS(HttpRequestBean httpRequestBean) {
        String combinedRequestData = decodeRequestData(httpRequestBean);
        String combinedResponseData = decodeResponseData(httpRequestBean.getHttpResponseBean());
        System.out.println("Processed request data is : " + combinedRequestData);
        System.out.println("Processed response data is : " + combinedResponseData);

         List<String> attackContructs = isXSS(combinedRequestData);

        for (String construct : attackContructs) {
			System.err.println(String.format(
					"Reflected XSS contruct detected ::  %s :: Request : %s", construct,
					httpRequestBean));
            if (StringUtils.containsIgnoreCase(combinedResponseData, construct)) {
                System.err.println(String.format(
                        "Reflected XSS attack detected :: Construct : %s :: Request : %s :: Response : %s", construct,
                        httpRequestBean, httpRequestBean.getHttpResponseBean().getResponseBody()));
                return construct;
            }
        }

        return StringUtils.EMPTY;
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

    private static List<String> isXSS(String combinedData) {
        List<String> attackConstructs = new ArrayList<>();
        System.out.println("Consolidated XSS data : " + combinedData);

        Matcher htmlStartTagMatcher = htmlStartTagExtractor.matcher(combinedData);
        while (htmlStartTagMatcher.find()) {
            if (StringUtils.isNotBlank(htmlStartTagMatcher.group(1))) {
                attackConstructs.add(htmlStartTagMatcher.group(1));
            } else if (StringUtils.isNotBlank(htmlStartTagMatcher.group(3))) {
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
                            if (StringUtils.startsWithIgnoreCase(attribKey, "on")
                                    && StringUtils.isNotBlank(attribVal)) {
                                Matcher functionCallMatcher = functionCallDetector.matcher(attribVal);
                                if (functionCallMatcher.find() && StringUtils.isNotBlank(attribMatcher.group())) {
                                    attackConstructs.add(attribMatcher.group());
                                    break;
                                }
                                // If other attrib is used for javascript injection
                            } else if (StringUtils.isNotBlank(attribVal)) {
                                if (StringUtils.containsIgnoreCase(attribVal, "javascript:")
                                        || StringUtils.endsWithIgnoreCase(attribVal, ".js")
                                        || StringUtils.startsWithIgnoreCase(attribVal, "http://")
                                        || StringUtils.startsWithIgnoreCase(attribVal, "https://")) {
                                    if (StringUtils.isNotBlank(attribMatcher.group())) {
                                        attackConstructs.add(attribMatcher.group());
                                    }
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

    public static String getConnectionInformation(Object ref, boolean needToGetConnection) {
        try {
            Object connection;
            if (needToGetConnection) {
                Method getConnection = ref.getClass().getMethod("getConnection", null);
                getConnection.setAccessible(true);
                connection = getConnection.invoke(ref, null);
            } else {
                connection = ref;
            }
            if (sqlConnectionMap.containsKey(connection.hashCode())) {
                JADatabaseMetaData metaData = sqlConnectionMap.get(connection.hashCode());
                return metaData.getDbIdentifier();
            } else {
                Method getMetaData = connection.getClass().getMethod("getMetaData", null);
                getMetaData.setAccessible(true);
                Object dbMetaData = getMetaData.invoke(connection, null);

                Method getDatabaseProductName = dbMetaData.getClass().getMethod("getDatabaseProductName", null);
                getDatabaseProductName.setAccessible(true);
                String productName = (String) getDatabaseProductName.invoke(dbMetaData, null);

                Method getDriverName = dbMetaData.getClass().getMethod("getDriverName", null);
                getDriverName.setAccessible(true);
                String driverName = (String) getDriverName.invoke(dbMetaData, null);

                Method getDriverVersion = dbMetaData.getClass().getMethod("getDriverVersion", null);
                getDriverVersion.setAccessible(true);
                String driverVersion = (String) getDriverVersion.invoke(dbMetaData, null);

                if (StringUtils.isNotBlank(productName)) {
                    JADatabaseMetaData jaDatabaseMetaData = new JADatabaseMetaData(productName);
                    jaDatabaseMetaData.setDriverName(driverName);
                    jaDatabaseMetaData.setDriverVersion(driverVersion);
                    jaDatabaseMetaData.setDriverClassName(connection.getClass().getName());
                    jaDatabaseMetaData.setDbIdentifier(detectDatabaseProduct(productName));
                    System.out.println("DB details detected: " + jaDatabaseMetaData);
                    sqlConnectionMap.put(connection.hashCode(), jaDatabaseMetaData);
                    return jaDatabaseMetaData.getDbIdentifier();
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return "UNKNOWN";
    }

    private static String detectDatabaseProduct(String databaseProductName) {

        if (databaseProductName.contains("MySQL")) {
            return "MYSQL";
        }
        if (databaseProductName.startsWith("Oracle")) {
            return "ORACLE";
        }
        if (databaseProductName.startsWith("Apache Derby")) {
            return "DERBY";
        }
        if (databaseProductName.contains("HSQL Database Engine")) {
            return "HSQL";
        }
        if (databaseProductName.startsWith("SQLite")) {
            return "SQLITE";
        }
        if (databaseProductName.startsWith("H2")) {
            return "H2";
        }
        if (databaseProductName.startsWith("Microsoft SQL Server")) {
            return "MSSQL";
        }
        if (databaseProductName.startsWith("EnterpriseDB")) {
            return "ENTERPRISEDB";
        }
        if (databaseProductName.startsWith("Phoenix")) {
            return "PHOENIX";
        }
        if (databaseProductName.startsWith("PostgreSQL")) {
            return "POSTGRESQL";
        }
        if (databaseProductName.startsWith("DB2")) {
            return "DB2";
        }
        if (databaseProductName.startsWith("Vertica")) {
            return "VERTICA";
        }
        if (databaseProductName.startsWith("Adaptive") || databaseProductName.startsWith("ASE") || databaseProductName
                .startsWith("sql server")) {
            return "SYBASE";
        }
        if (databaseProductName.startsWith("HDB")) {
            return "SAPANA";
        }
        if (databaseProductName.startsWith("Greenplum")) {
            return "GREENPLUM";
        }
        if (databaseProductName.contains("solidDB")) {
            return "SOLIDDB";
        }
        if (StringUtils.containsIgnoreCase(databaseProductName, "maria")) {
        	return "MARIADB";
        }
        return "UNKNOWN";
    }

    public static String decodeResponseData(HttpResponseBean httpResponseBean) {
        StringBuilder consolidatedBody = new StringBuilder();
        String contentType = httpResponseBean.getResponseContentType();
        String responseBody = httpResponseBean.getResponseBody();
        String processedBody = responseBody;

        String processedHeaders = httpResponseBean.getHeaders().toString();
        String oldHeaders = processedHeaders;

        try {
            consolidatedBody.append(processedBody);
            consolidatedBody.append("::::");

            processedBody = HtmlEscape.unescapeHtml(responseBody);
            consolidatedBody.append(processedBody);
            consolidatedBody.append("::::");

            consolidatedBody.append(processedHeaders);
            consolidatedBody.append("::::");

            processedHeaders = HtmlEscape.unescapeHtml(processedHeaders);
            consolidatedBody.append(processedHeaders);
            consolidatedBody.append("::::");


            processedBody = urlDecode(processedBody);
            consolidatedBody.append("::::");
            consolidatedBody.append(processedBody);

            processedHeaders = urlDecode(processedHeaders);
            consolidatedBody.append(processedHeaders);
            consolidatedBody.append("::::");

            String oldProcessedBody;

            if (StringUtils.isNoneEmpty(responseBody)) {
                switch (contentType) {
                case "application/json":
                    do {
                        oldProcessedBody = processedBody;
                        processedBody = StringEscapeUtils.unescapeJson(processedBody);
                        if(!StringUtils.equals(oldProcessedBody, processedBody)) {
                            consolidatedBody.append("::::");
                            consolidatedBody.append(processedBody);
                            System.out.println("Decoding JSON: " + processedBody);
                        }
                    } while (!StringUtils.equals(oldProcessedBody, processedBody));
                    break;
                case "application/xml":
                    do {
                        oldProcessedBody = processedBody;
                        processedBody = StringEscapeUtils.unescapeXml(processedBody);
                        if(!StringUtils.equals(oldProcessedBody, processedBody)) {
                            consolidatedBody.append("::::");
                            consolidatedBody.append(processedBody);
                            System.out.println("Decoding XML: " + processedBody);
                        }
                    } while (!StringUtils.equals(oldProcessedBody, processedBody));
                    break;

                }
            }
            return consolidatedBody.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return StringUtils.EMPTY;
    }

    public static String decodeRequestData(HttpRequestBean httpRequestBean) {
        StringBuilder consolidatedBody = new StringBuilder();
        String contentType = httpRequestBean.getContentType();
        String body = httpRequestBean.getBody();
        String processedUrl = httpRequestBean.getUrl();
        String oldUrl = processedUrl;
        String processedBody = body;

        String processedHeaders = httpRequestBean.getHeaders().toString();
        String oldHeaders = processedHeaders;

        try {
            consolidatedBody.append(oldHeaders);
            consolidatedBody.append("::::");
            consolidatedBody.append(HtmlEscape.unescapeHtml(oldHeaders));
            consolidatedBody.append("::::");
            consolidatedBody.append(processedBody);
            consolidatedBody.append("::::");
            consolidatedBody.append(HtmlEscape.unescapeHtml(processedBody));

            // For URL
            consolidatedBody.append("::::");
            consolidatedBody.append(processedUrl);
            do {
                oldUrl = processedUrl;
                processedUrl = urlDecode(processedUrl);
                if(!StringUtils.equals(oldUrl, processedUrl)) {
                    consolidatedBody.append("::::");
                    consolidatedBody.append(processedUrl);
                    System.out.println("Decoding URL Line: " + processedUrl);
                }
            } while (!StringUtils.equals(oldUrl, processedUrl));

            do {
                oldHeaders = processedHeaders;
                processedHeaders = urlDecode(processedHeaders);
                if (!StringUtils.equals(oldHeaders, processedHeaders)){
                    consolidatedBody.append("::::");
                    consolidatedBody.append(processedHeaders);
                    System.out.println("Decoding URL Headers: " + processedHeaders);
                }
            } while (!StringUtils.equals(oldHeaders, processedHeaders));

            if (StringUtils.isNotBlank(processedBody)) {
                String oldProcessedBody;
                switch (contentType) {
                case "application/json":
                    do {
                        oldProcessedBody = processedBody;
                        processedBody = StringEscapeUtils.unescapeJson(processedBody);
                        if(!StringUtils.equals(oldProcessedBody, processedBody)) {
                            consolidatedBody.append("::::");
                            consolidatedBody.append(processedBody);
                            System.out.println("Decoding JSON: " + processedBody);
                        }
                    } while (!StringUtils.equals(oldProcessedBody, processedBody));
                    break;
                case "application/xml":
                    do {
                        oldProcessedBody = processedBody;
                        processedBody = StringEscapeUtils.unescapeXml(processedBody);
                        if(!StringUtils.equals(oldProcessedBody, processedBody)) {
                            consolidatedBody.append("::::");
                            consolidatedBody.append(processedBody);
                            System.out.println("Decoding XML: " + processedBody);
                        }
                    } while (!StringUtils.equals(oldProcessedBody, processedBody));
                    break;

                case "application/x-www-form-urlencoded":
                    processedBody = urlDecode(processedBody);
                    consolidatedBody.append("::::");
                    consolidatedBody.append(processedBody);

                    do {
                        oldProcessedBody = processedBody;
                        processedBody = urlDecode(processedBody);
                        if(!StringUtils.equals(oldProcessedBody, processedBody)) {
                            consolidatedBody.append("::::");
                            consolidatedBody.append(processedBody);
                            System.out.println("Decoding URL: " + processedBody);
                        }
                    } while (!StringUtils.equals(oldProcessedBody, processedBody));


                    break;
                }
            }
            return consolidatedBody.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return StringUtils.EMPTY;
    }

}
