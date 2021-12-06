package com.k2cybersecurity.intcodeagent.logging;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.constants.MapConstants;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.*;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.File;
import java.io.ObjectInputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.k2cybersecurity.intcodeagent.constants.MapConstants.*;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.*;

//import org.brutusin.commons.json.spi.JsonCodec;

public class ProcessorThread implements Runnable {


    private static final Pattern PATTERN;
    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    private Object source;
    private Object[] arg;
    private Long executionId;
    private StackTraceElement[] stackTrace;
    private Long threadId;
    private String sourceString;
    private ObjectMapper mapper;
    private JSONParser parser;
    private Long preProcessingTime;
    private HttpRequestBean httpRequest;
    private FileIntegrityBean fileIntegrityBean;
    private VulnerabilityCaseType vulnerabilityCaseType;

    static {
        PATTERN = Pattern.compile(IAgentConstants.TRACE_REGEX);
    }

    /**
     * @param source
     * @param arg
     * @param executionId
     * @param stackTrace
     * @param tId
     * @param preProcessingTime
     */

    public ProcessorThread(Object source, Object[] arg, Long executionId, StackTraceElement[] stackTrace, long tId,
                           String sourceString, long preProcessingTime, HttpRequestBean httpRequest) {
        this.source = source;
        this.arg = arg;
        this.executionId = executionId;
        this.stackTrace = stackTrace;
        this.threadId = tId;
        this.sourceString = sourceString;
        this.mapper = new ObjectMapper();
        this.parser = new JSONParser();
        this.preProcessingTime = preProcessingTime;
        this.httpRequest = httpRequest;
    }

    public ProcessorThread(Object source, String[] arg, Long executionId, Long tId, FileIntegrityBean fileIntegrityBean,
                           HttpRequestBean httpRequest, VulnerabilityCaseType fileIntegrity) {
        this.sourceString = JAVA_IO_FILE;
        this.source = source;
        this.arg = arg;
        this.executionId = executionId;
        this.threadId = tId;
        this.mapper = new ObjectMapper();
        this.parser = new JSONParser();
        this.httpRequest = httpRequest;
        this.fileIntegrityBean = fileIntegrityBean;
        this.vulnerabilityCaseType = fileIntegrity;
    }

    /**
     * @return the source
     */
    public Object getSource() {
        return source;
    }

    /**
     * @param source the source to set
     */
    public void setSource(Object source) {
        this.source = source;
    }

    /**
     * @return the arg
     */
    public Object[] getArg() {
        return arg;
    }

    /**
     * @param arg the arg to set
     */
    public void setArg(Object[] arg) {
        this.arg = arg;
    }

    /**
     * @return the executionId
     */
    public Long getExecutionId() {
        return executionId;
    }

    /**
     * @param executionId the executionId to set
     */
    public void setExecutionId(Long executionId) {
        this.executionId = executionId;
    }

    @Override
    public void run() {
        try {
            if (JAVA_IO_FILE.equals(sourceString)) {
                generateFileIntegrityEvent();
                return;
            }
            if (EXECUTORS.containsKey(sourceString)) {
                long start = System.currentTimeMillis();

                JavaAgentEventBean intCodeResultBean = new JavaAgentEventBean(start, preProcessingTime, sourceString,
                        K2Instrumentator.VMPID, K2Instrumentator.APPLICATION_UUID,
                        this.threadId + IAgentConstants.COLON_SEPERATOR + this.executionId,
                        EXECUTORS.get(sourceString));

                String klassName = null;

                if (MONGO_EXECUTORS.containsKey(sourceString)) {
                    intCodeResultBean.setEventCategory(MONGO);
                }

                StackTraceElement[] trace = this.stackTrace;

                String lastNonJavaClass = StringUtils.EMPTY;
                String lastNonJavaMethod = StringUtils.EMPTY;
                int lastNonJavaLineNumber = 0;

                JSONArray params = toString(arg, sourceString, EXECUTORS.get(sourceString));
                if (params != null && !params.isEmpty()) {
                    intCodeResultBean.setParameters(params);
                } else {
                    return;
                }
                if (VulnerabilityCaseType.FILE_OPERATION
                        .equals(VulnerabilityCaseType.valueOf(intCodeResultBean.getCaseType()))
                        && allowedExtensionFileIO(params)) {
                    intCodeResultBean.setValidationBypass(true);
                    K2Instrumentator.JA_HEALTH_CHECK.incrementDropCount();
                    return;
                }

                boolean userclassFound = false;
                for (int i = 0; i < trace.length; i++) {
//					logger.log(LogLevel.SEVERE, "\t\t : "+ trace[i].toString(), ProcessorThread.class.getName());
                    int lineNumber = trace[i].getLineNumber();
                    klassName = trace[i].getClassName();

                    if (!StringUtils.contains(trace[i].toString(), DOT_JAVA_COLON) && i > 0
                            && StringUtils.contains(trace[i - 1].toString(), DOT_JAVA_COLON)) {
                        intCodeResultBean.getMetaData().setTriggerViaRCI(true);
                        intCodeResultBean.getMetaData().getRciMethodsCalls().add(trace[i].toString());
                        intCodeResultBean.getMetaData().getRciMethodsCalls().add(trace[i - 1].toString());
//						logger.log(LogLevel.DEBUG,
//								String.format(PRINTING_STACK_TRACE_FOR_PROBABLE_RCI_EVENT_S_S,
//										intCodeResultBean.getId(), Arrays.asList(trace)),
//								ProcessorThread.class.getName());
                    }


                    if (MapConstants.MYSQL_GET_CONNECTION_MAP.containsKey(klassName)
                            && MapConstants.MYSQL_GET_CONNECTION_MAP.get(klassName)
                            .contains(trace[i].getMethodName())) {
                        intCodeResultBean.setValidationBypass(true);
                        K2Instrumentator.JA_HEALTH_CHECK.incrementDropCount();
                        return;
                    }

                    Matcher matcher = PATTERN.matcher(klassName);
                    if (StringUtils.contains(klassName, REFLECT_NATIVE_METHOD_ACCESSOR_IMPL)
                            && StringUtils.equals(trace[i].getMethodName(), INVOKE_0) && i > 0) {
                        intCodeResultBean.getMetaData().setTriggerViaRCI(true);
                        intCodeResultBean.getMetaData().getRciMethodsCalls().add(trace[i - 1].toString());
//						logger.log(
//								LogLevel.DEBUG, String.format(PRINTING_STACK_TRACE_FOR_RCI_EVENT_S_S,
//										intCodeResultBean.getId(), Arrays.asList(trace)),
//								ProcessorThread.class.getName());
                    }

                    if ((StringUtils.contains(klassName, XML_DOCUMENT_FRAGMENT_SCANNER_IMPL)
                            && StringUtils.equals(trace[i].getMethodName(), SCAN_DOCUMENT))
                            || (StringUtils.contains(klassName, XML_ENTITY_MANAGER)
                            && StringUtils.equals(trace[i].getMethodName(), SETUP_CURRENT_ENTITY))) {
                        intCodeResultBean.getMetaData().setTriggerViaXXE(true);
//						logger.log(LogLevel.DEBUG, String.format(PRINTING_STACK_TRACE_FOR_XXE_EVENT_S_S, intCodeResultBean.getId(), Arrays
//								.asList(trace)), ProcessorThread.class.getName());
                    }

                    if (ObjectInputStream.class.getName().equals(klassName)
                            && StringUtils.equals(trace[i].getMethodName(), READ_OBJECT)) {
                        intCodeResultBean.getMetaData().setTriggerViaDeserialisation(true);
//						logger.log(LogLevel.DEBUG,
//								String.format(PRINTING_STACK_TRACE_FOR_DESERIALISE_EVENT_S_S,
//										intCodeResultBean.getId(), Arrays.asList(trace)),
//								ProcessorThread.class.getName());

                    }
                    if (HSQL_GET_CONNECTION_MAP.containsKey(klassName)
                            && HSQL_GET_CONNECTION_MAP.get(klassName).contains(trace[i].getMethodName())) {
                        intCodeResultBean.setValidationBypass(true);
                        K2Instrumentator.JA_HEALTH_CHECK.incrementDropCount();
                        return;
                    }

                    if (lineNumber <= 0)
                        continue;

                    if (!matcher.matches() && !userclassFound) {
                        intCodeResultBean.setUserAPIInfo(lineNumber, klassName, trace[i].getMethodName());
                        if (i > 0) {
                            intCodeResultBean.setCurrentMethod(trace[i - 1].getMethodName());
                        }
                        userclassFound = true;
                    } else if (!userclassFound && StringUtils.isNotBlank(matcher.group(5))) {
                        lastNonJavaClass = trace[i].getClassName();
                        lastNonJavaMethod = trace[i].getMethodName();
                        lastNonJavaLineNumber = trace[i].getLineNumber();
                    }
                }
                if (intCodeResultBean.getUserFileName() != null && !intCodeResultBean.getUserFileName().isEmpty()) {
                    generateEvent(intCodeResultBean);
                } else if (IAgentConstants.SYSYTEM_CALL_START.equals(sourceString)) {
                    int traceId = getClassNameForSysytemCallStart(trace, intCodeResultBean);
                    intCodeResultBean.setUserAPIInfo(trace[traceId].getLineNumber(), klassName,
                            trace[traceId].getMethodName());
                    intCodeResultBean.setParameters(toString(arg, sourceString, EXECUTORS.get(sourceString)));
                    if (traceId > 0)
                        intCodeResultBean.setCurrentMethod(trace[traceId - 1].getMethodName());
                    generateEvent(intCodeResultBean);
                } else {
                    if (params != null) {
                        intCodeResultBean.setParameters(params);
                        intCodeResultBean.setUserAPIInfo(lastNonJavaLineNumber, lastNonJavaClass, lastNonJavaMethod);
                    }
                    generateEvent(intCodeResultBean);
                }
            }
        } catch (Throwable e) {
            logger.log(LogLevel.WARN, "Error in run: ", e, ProcessorThread.class.getName());
        } finally {
            ServletEventPool.getInstance().decrementServletInfoReference(threadId, executionId, true);
        }
    }

    private void generateFileIntegrityEvent() {
        long start = System.currentTimeMillis();
        JavaAgentEventBean intCodeResultBean = new JavaAgentEventBean(start, preProcessingTime, sourceString,
                K2Instrumentator.VMPID, K2Instrumentator.APPLICATION_UUID,
                this.threadId + IAgentConstants.COLON_SEPERATOR + this.executionId,
                VulnerabilityCaseType.FILE_OPERATION);
        JSONArray param = new JSONArray();
        param.add(arg[0]);
        intCodeResultBean.setParameters(param);
        intCodeResultBean.setUserAPIInfo(fileIntegrityBean.getLineNumber(), fileIntegrityBean.getUserFileName(),
                fileIntegrityBean.getUserMethodName());
        intCodeResultBean.setCurrentMethod(fileIntegrityBean.getCurrentMethod());
        intCodeResultBean.setCaseType(this.vulnerabilityCaseType.getCaseType());
        intCodeResultBean.setHttpRequest(new HttpRequestBean(this.httpRequest));
        intCodeResultBean.setEventGenerationTime(System.currentTimeMillis());
        intCodeResultBean.getHttpRequest().clearRawRequest();
        EventSendPool.getInstance().sendEvent(intCodeResultBean.toString());
        K2Instrumentator.JA_HEALTH_CHECK.incrementEventSentCount();
    }

    private boolean allowedExtensionFileIO(JSONArray params) {
        if (JAVA_IO_FILE_INPUTSTREAM_OPEN.equals(this.sourceString)) {
            for (int i = 0; i < params.size(); i++) {
                String filePath = params.get(i).toString();
                String extension = StringUtils.EMPTY;

                int k = filePath.lastIndexOf('.');
                if (k > 0) {
                    extension = filePath.substring(k + 1).toLowerCase();

                }
                if (ALLOWED_EXTENSIONS.contains(extension))
                    return true;
            }
        }
        return false;
    }

    private int getClassNameForSysytemCallStart(StackTraceElement[] trace, JavaAgentEventBean intCodeResultBean) {
        boolean classRuntimeFound = false;
        for (int i = 0; i < trace.length; i++) {
            if (trace[i].getClassName().equals(IAgentConstants.JAVA_LANG_RUNTIME))
                classRuntimeFound = true;
            else if (classRuntimeFound)
                return i;
        }
        return -1;
    }

    /**
     * This method is used for MSSQL parameter Extraction
     *
     * @param obj        the object in argument of Instrumented Method
     * @param parameters the parameter list as a JSONArray
     * @return void
     * @throws NoSuchFieldException     the no such field exception
     * @throws SecurityException        the security exception
     * @throws IllegalArgumentException the illegal argument exception
     * @throws IllegalAccessException   the illegal access exception
     */
    @SuppressWarnings(UNCHECKED)
    private static void getMSSQLParameterValue(Object obj, JSONArray parameters)
            throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        String className = obj.getClass().getCanonicalName();

        // Extraction of Connection params
        {
            Field field = obj.getClass().getDeclaredField(MSSQL_CURRENT_OBJECT);
            field.setAccessible(true);
            Object child = field.get(obj);
            Field childField = null;

            if (child.getClass().getName().equals(MSSQL_SERVER_STATEMENT_CLASS)) {
                childField = child.getClass().getDeclaredField(MSSQL_CONNECTION_FIELD);
            } else if (child.getClass().getName().equals(MSSQL_PREPARED_STATEMENT_CLASS)) {
                childField = child.getClass().getSuperclass().getDeclaredField(MSSQL_CONNECTION_FIELD);
            } else {
                childField = child.getClass().getSuperclass().getSuperclass().getDeclaredField(MSSQL_CONNECTION_FIELD);
            }
            childField.setAccessible(true);

            child = childField.get(child);
            childField = child.getClass().getDeclaredField(MSSQL_ACTIVE_CONNECTION_PROP_FIELD);
            childField.setAccessible(true);

            Properties connectionProperties = (Properties) childField.get(child);
            parameters.add(connectionProperties.toString());
        }

        // Extraction of query for different query methods
        if (className.contains(MSSQL_PREPARED_STATEMENT_CLASS)) {
            Field field = obj.getClass().getDeclaredField(MSSQL_STATEMENT_FIELD);

            field.setAccessible(true);
            Object child = field.get(obj);

            // extract Query
            Field childField = null;
            if (child.getClass().getName().equals(MSSQL_PREPARED_STATEMENT_CLASS)) {
                childField = child.getClass().getDeclaredField(MSSQL_USER_SQL_FIELD);
            } else {
                // for JAVA compilation before 7.1, an instance of class
                // com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement42 is
                // made instead of
                // com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement
                childField = child.getClass().getSuperclass().getDeclaredField(MSSQL_USER_SQL_FIELD);
            }
            childField.setAccessible(true);
            parameters.add(childField.get(child));

            ArrayList<Object[]> params = null;

            // extract Values passed to Prepared Statement
            if (className.equals(MSSQL_PREPARED_BATCH_STATEMENT_CLASS)) {

                if (child.getClass().getName().equals(MSSQL_PREPARED_STATEMENT_CLASS)) {
                    childField = child.getClass().getDeclaredField(MSSQL_BATCH_PARAM_VALUES_FIELD);
                } else {
                    childField = child.getClass().getSuperclass().getDeclaredField(MSSQL_BATCH_PARAM_VALUES_FIELD);
                }
                childField.setAccessible(true);
                params = (ArrayList<Object[]>) childField.get(child);

            } else {

                if (child.getClass().getName().equals(MSSQL_PREPARED_STATEMENT_CLASS)) {
                    childField = child.getClass().getSuperclass().getDeclaredField(MSSQL_IN_OUT_PARAM_FIELD);
                } else {
                    // for JAVA compilation before 7.1, an instance of class
                    // com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement42
                    // is made instead of
                    // com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement
                    childField = child.getClass().getSuperclass().getSuperclass()
                            .getDeclaredField(MSSQL_IN_OUT_PARAM_FIELD);
                }
                childField.setAccessible(true);

                Object[] outParams = (Object[]) childField.get(child);
                params = new ArrayList<Object[]>();
                params.add(outParams);
            }
            addParamValuesMSSQL(params, parameters);

        } else if (className.equals(MSSQL_STATEMENT_EXECUTE_CMD_CLASS)) {
            Field field = obj.getClass().getDeclaredField(IAgentConstants.SQL);
            field.setAccessible(true);
            parameters.add(field.get(obj));

        } else if (className.equals(MSSQL_BATCH_STATEMENT_EXECUTE_CMD_CLASS)) {
            Field field = obj.getClass().getDeclaredField(MSSQL_STATEMENT_FIELD);
            field.setAccessible(true);
            Object child = field.get(obj);
            Field childField = child.getClass().getDeclaredField(MSSQL_BATCH_STATEMENT_BUFFER_FIELD);
            childField.setAccessible(true);
            ArrayList<String> queries = (ArrayList<String>) childField.get(child);
            parameters.add(queries.size());
            for (Object query : queries) {
                parameters.add(query);
            }

        } else if (className.equals(MSSQL_STATEMENT_EXECUTE_CMD_CLASS)) {
            Field field = obj.getClass().getDeclaredField(MSSQL_SQL_FIELD);
            field.setAccessible(true);
            parameters.add(field.get(obj));
        } else {

        }

    }

    /**
     * Gets the MySQL parameter values.
     *
     * @param args       the arguments of Instrumented Method
     * @param parameters the parameters
     * @return the my SQL parameter value
     */
    @SuppressWarnings(UNCHECKED)
    private void getMySQLParameterValue(Object[] args, JSONArray parameters, String sourceString) {
        try {
            int sqlObjectLocation = 1;
            int thisPointerLocation = args.length - 1;
            if (args[thisPointerLocation].getClass().getName().equals(String.class.getName())) {
                sqlObjectLocation = thisPointerLocation;
            }
            parameters.add(String.valueOf(arg[sqlObjectLocation]));

        } catch (Throwable e) {
            logger.log(LogLevel.WARN, ERROR_IN_GET_MY_SQL_PARAMETER_VALUE, e, ProcessorThread.class.getName());
        }
    }

    public static void getMongoDbParameterValue(Object[] args, JSONArray parameters) {
        JSONObject queryDetailObj = new JSONObject();
        Object protocol = args[0];
        Field f = null;
//		System.out.println("protocol class : " + protocol.getClass());
        try {
            Class<? extends Object> nsClass = protocol.getClass();
            String namespace = null;
            // Namespace detection
            if (nsClass != null) {
                f = nsClass.getDeclaredField(MONGO_NAMESPACE_FIELD);
                f.setAccessible(true);
                Object ns = f.get(protocol);
                namespace = ns.toString();
                queryDetailObj.put(MONGO_NAMESPACE_FIELD, namespace);
            }
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            // TODO Auto-generated catch block
        }
        // query extreation
        try {
            // Class used CommandProtocol<T>
//			System.out.println("inside CommandProtocol");
            f = protocol.getClass().getDeclaredField(MONGO_COMMAND_FIELD);
            f.setAccessible(true);
            Object command = f.get(protocol);
            queryDetailObj.put(COMMAND, new JSONParser().parse(command.toString()));
            parameters.add(queryDetailObj);
            return;
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException
                | ParseException e) {
            // TODO Auto-generated catch block
        }
        try {
            // Class used QueryProtocol<T>
            f = protocol.getClass().getDeclaredField(QUERY_DOCUMENT);
            f.setAccessible(true);
            Object command = f.get(protocol);
            queryDetailObj.put(COMMAND, new JSONParser().parse(command.toString()));
            f = protocol.getClass().getDeclaredField(FIELDS);
            f.setAccessible(true);
            Object fields = f.get(protocol);
            queryDetailObj.put(FIELDS, new JSONParser().parse(fields.toString()));
            parameters.add(queryDetailObj);
            return;
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException
                | ParseException e) {
            // TODO Auto-generated catch block
        }
        try {
            // Class used InsertCommandProtocol<T>
            queryDetailObj.put(COMMAND, mongoProtocolRequest(protocol, MONGO_INSERT_REQUESTS_FIELD));
            parameters.add(queryDetailObj);
            return;
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            // TODO Auto-generated catch block
        }
        try {
            // Class used DeleteCommandProtocol<T>
            queryDetailObj.put(COMMAND, mongoProtocolRequest(protocol, MONGO_DELETE_REQUEST_FIELD));
            parameters.add(queryDetailObj);
            return;
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            // TODO Auto-generated catch block
        }
        try {
            // Class used UpdateCommandProtocol<T>
            queryDetailObj.put(COMMAND, mongoProtocolRequest(protocol, MONGO_MULTIPLE_UPDATES_FIELD));
            parameters.add(queryDetailObj);
            return;
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            // TODO Auto-generated catch block
        }
        try {
            // Class used InsertProtocol<T>
            queryDetailObj.put(COMMAND, mongoProtocolRequest(protocol, MONGO_INSERT_REQUEST_LIST_FIELD));
            parameters.add(queryDetailObj);
            return;
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            // TODO Auto-generated catch block
        }
        try {
            // Class used DeleteProtocol<T>
            queryDetailObj.put(COMMAND, mongoProtocolRequest(protocol, DELETES));
            parameters.add(queryDetailObj);
//			System.out.println("parameters : " + parameters);
            return;
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            // TODO Auto-generated catch block
        }
        try {
            // Class used UpdateProtocol<T>
            queryDetailObj.put(COMMAND, mongoProtocolRequest(protocol, MONGO_MULTIPLE_UPDATES_FIELD));
            parameters.add(queryDetailObj);
            return;
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
            // TODO Auto-generated catch block
        }
    }

    private static JSONObject mongoProtocolRequest(Object protocol, String requestField)
            throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        JSONObject object = new JSONObject();
        Field f;
        f = protocol.getClass().getDeclaredField(requestField);
        f.setAccessible(true);
        List<Object> insertRequests = (List<Object>) f.get(protocol);
        for (Object request : insertRequests) {
            Field[] fields = request.getClass().getDeclaredFields();
            for (Field field : fields) {
                field.setAccessible(true);
                Object bsonDoc = field.get(request);
                if (bsonDoc != null && bsonDoc.getClass().getSimpleName().contains(BSONDOCUMENT)) {
                    try {
                        object.put(field.getName(), new JSONParser().parse(bsonDoc.toString()));
                    } catch (Throwable e) {
                        logger.log(LogLevel.ERROR, "Error :", e, ProcessorThread.class.getName());
                    }
                }
            }
        }
        return object;
    }

    /**
     * @param parameters
     */
    private void getClassLoaderParameterValue(Object[] args, JSONArray parameters) {
        for (Object obj : args) {
            try {
                JSONArray jsonArray = (JSONArray) parser.parse(mapper.writeValueAsString(obj));
                for (int i = 0; i < jsonArray.size(); i++) {
                    String value = jsonArray.get(i).toString();
                    if (value.startsWith(IAgentConstants.FILE_URL)) {
                        parameters.add(value.substring(7));
                    }
                }
            } catch (Throwable e) {
            }
        }

    }

    /**
     * @param parameters
     */
    private JSONArray getOracleParameterValue(Object thisPointer, JSONArray parameters, String sourceString) {

        Class<?> thisPointerClass = thisPointer.getClass();
        try {
            if (ORACLE_CLASS_SKIP_LIST.contains(thisPointerClass.getName())) {
                return null;
            }
            // in case of doRPC()
            if (thisPointerClass.getName().contains(ORACLE_CONNECTION_IDENTIFIER)) {

                Field cursorField = thisPointerClass.getDeclaredField(IAgentConstants.CURSOR);
                cursorField.setAccessible(true);
                Object cursor = cursorField.get(thisPointer);

                // ignore batch fetch events
                if (!String.valueOf(cursor).equals(IAgentConstants.ZERO)
                        || String.valueOf(cursor).equals(IAgentConstants.NULL)) {
                    return null;
                }

                Field oracleStatementField = thisPointerClass.getDeclaredField(IAgentConstants.ORACLESTATEMENT);
                oracleStatementField.setAccessible(true);
                Object oracleStatement = oracleStatementField.get(thisPointer);

                Class<?> statementKlass = oracleStatement.getClass();
                while (!statementKlass.getName().equals(ORACLE_STATEMENT_CLASS_IDENTIFIER)) {
                    statementKlass = statementKlass.getSuperclass();
                }

                Field sqlObjectField = statementKlass.getDeclaredField(IAgentConstants.SQLOBJECT);
                sqlObjectField.setAccessible(true);
                Object sqlObject = sqlObjectField.get(oracleStatement);

                parameters.add(String.valueOf(sqlObject));

            }
        } catch (Throwable e) {
            logger.log(LogLevel.WARN, ERROR_IN_GET_ORACLE_PARAMETER_VALUE, e, ProcessorThread.class.getName());
        }
        return parameters;
    }

    /**
     * This method is used to extract All the required parameters through the
     * arguments of instrumented method
     *
     * @param obj the obj
     * @return the JSON array
     */
    @SuppressWarnings({UNCHECKED, UNUSED})
    private JSONArray toString(Object[] obj, String sourceString, VulnerabilityCaseType vulnerabilityCaseType) {

        if (obj == null) {
            return null;
        }
        JSONArray parameters = new JSONArray();
        try {
            if (obj[0] != null && sourceString.contains(MSSQL_IDENTIFIER)) {
                getMSSQLParameterValue(obj[0], parameters);
            } else if (sourceString.contains(MYSQL_IDENTIFIER)) {
                getMySQLParameterValue(obj, parameters, sourceString);
            } else if (obj[0] != null && sourceString.contains(MONGO_IDENTIFIER)) {
                getMongoDbParameterValue(obj, parameters);
            } else if (obj[0] != null && sourceString.contains(ORACLE_IDENTIFIER)) {
                parameters = getOracleParameterValue(arg[arg.length - 1], parameters, sourceString);
            } else if (obj[0] != null && sourceString.contains(CLASS_LOADER_IDENTIFIER)) {
                getClassLoaderParameterValue(obj, parameters);
            } else if (sourceString.equals(PSQLV3_EXECUTOR) || sourceString.equals(PSQLV2_EXECUTOR)
                    || sourceString.equals(PSQL42_EXECUTOR) || sourceString.equals(PSQLV3_EXECUTOR7_4)) {
                getPSQLParameterValue(obj, parameters);
            } else if (sourceString.equals(HSQL_V2_4) || sourceString.equals(HSQL_V1_8_CONNECTION)
                    || sourceString.equals(HSQL_V1_8_SESSION) || sourceString.equals(HSQL_V2_3_4_CLIENT_CONNECTION)) {
                getHSQLParameterValue(obj[0], parameters);
            } else if (sourceString.equals(APACHE_HTTP_REQUEST_EXECUTOR_METHOD)) {
                getApacheHttpRequestParameters(obj, parameters);
            } else if (sourceString.equals(JAVA_OPEN_CONNECTION_METHOD2)
                    || sourceString.equals(JAVA_OPEN_CONNECTION_METHOD2_HTTPS)
                    || sourceString.equals(JAVA_OPEN_CONNECTION_METHOD2_HTTPS_2)
                    || sourceString.equals(WEBLOGIC_OPEN_CONNECTION_METHOD)) {
                getJavaHttpRequestParameters(obj, parameters);
            } else if (sourceString.equals(JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_METHOD)
                    || sourceString.equals(JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_ASYNC_METHOD)) {
                getJava9HttpClientParameters(obj, parameters);
//			} else if (vulnerabilityCaseType.equals(VulnerabilityCaseType.FILE_OPERATION)) {
//				getFileParameters(obj, parameters);
            } else if (sourceString.equals(APACHE_COMMONS_HTTP_METHOD_DIRECTOR_METHOD)) {
                getApacheCommonsHttpRequestParameters(obj, parameters);
            } else if (sourceString.equals(OKHTTP_HTTP_ENGINE_METHOD)) {
                getOkHttpRequestParameters(obj, parameters);
            } else {
                for (int i = 0; i < obj.length; i++) {
                    Object json = parser.parse(mapper.writeValueAsString(obj[i]));
                    parameters.add(json);
                }
            }

        } catch (Throwable th) {
            parameters.add((obj != null) ? obj.toString() : null);
            logger.log(LogLevel.WARN, ERROR_IN_TO_STRING, th, ProcessorThread.class.getName());
        }
        return parameters;
    }

    private void getFileParameters(Object[] obj, JSONArray parameters) {
        if (obj[0].getClass().getName().equals(SUN_NIO_FS_UNIX_PATH)) {
            parameters.add(obj[0].toString());
        } else if (obj[0].getClass().getName().equals(JAVA_IO_FILE)) {
            parameters.add(((File) obj[0]).toString());
        } else {
            parameters.add(obj[0]);
        }
    }

    @SuppressWarnings(UNCHECKED)
    public static void getJavaHttpRequestParameters(Object[] obj, JSONArray parameters) {

        URL url = (URL) obj[0];
        parameters.add(url.getHost());
        parameters.add(url.getPath());

    }

    @SuppressWarnings(UNCHECKED)
    public static void getJava9HttpClientParameters(Object[] obj, JSONArray parameters) {
        Object multiExchangeObj = obj[0];
        try {

            Class<?> multiExchangeClass = Thread.currentThread().getContextClassLoader()
                    .loadClass(JDK_INCUBATOR_HTTP_MULTI_EXCHANGE);
            Field request = multiExchangeClass.getDeclaredField(REQUEST);
            request.setAccessible(true);
            Object httpReqObj = request.get(multiExchangeObj);

            Field uri = httpReqObj.getClass().getDeclaredField(URI);
            uri.setAccessible(true);
            URI uriObj = (URI) uri.get(httpReqObj);

            parameters.add(uriObj.getHost());
            parameters.add(uriObj.getPath());

        } catch (Throwable e) {
            logger.log(LogLevel.WARN, ERROR_IN_GET_JAVA9_HTTP_CLIENT_PARAMETERS, e,
                    ProcessorThread.class.getName());
        }
    }

    @SuppressWarnings(UNCHECKED)
    public static void getApacheHttpRequestParameters(Object[] object, JSONArray parameters) {

        Object request = object[0];
        Object httpContext = object[2];
        try {
            Class<?> httpClientInterface;
            Class<?> httpContextInterface;
            ClassLoader requestLoader = request.getClass().getClassLoader();
            ClassLoader httpContextLoader = httpContext.getClass().getClassLoader();
            if (requestLoader != null) {
                httpClientInterface = Class.forName(ORG_APACHE_HTTP_HTTP_REQUEST, true, requestLoader);
            } else {
                httpClientInterface = Class.forName(ORG_APACHE_HTTP_HTTP_REQUEST, true,
                        Thread.currentThread().getContextClassLoader());
            }

            if (httpContextLoader != null) {
                httpContextInterface = Class.forName(ORG_APACHE_HTTP_PROTOCOL_HTTP_CONTEXT, true, httpContextLoader);
            } else {
                httpContextInterface = Class.forName(ORG_APACHE_HTTP_PROTOCOL_HTTP_CONTEXT, true,
                        Thread.currentThread().getContextClassLoader());
            }
            Method getRequestLine = httpClientInterface.getMethod(GET_REQUEST_LINE);
            Object requestLine = getRequestLine.invoke(request);

            String requestLineStr = requestLine.toString();
            String[] requestLineTokens = requestLineStr.split(REGEX_SPACE);
            String requestUri = requestLineTokens[1];
            Method getAttribute = httpContextInterface.getMethod(GET_ATTRIBUTE, String.class);
            Object attributeHost = getAttribute.invoke(httpContext, HTTP_TARGET_HOST);

            int indexOfQmark = requestUri.indexOf(QUESTION_MARK);
            // means request param is present
            String pathOnly = EMPTY;
            if (indexOfQmark != -1) {
                pathOnly = requestUri.substring(0, indexOfQmark);
            }

            parameters.add(attributeHost.toString());
            parameters.add(pathOnly);

        } catch (Throwable e) {
            logger.log(LogLevel.WARN, ERROR_IN_GET_APACHE_HTTP_REQUEST_PARAMETERS, e,
                    ProcessorThread.class.getName());
        }

    }

    public static void getApacheCommonsHttpRequestParameters(Object[] object, JSONArray parameters) {

        Object httpMethod = object[0];
        try {
            Class<?> httpMethodInterface;
            Class<?> httpURI;
            ClassLoader httpMethodLoader = httpMethod.getClass().getClassLoader();
            if (httpMethodLoader != null) {
                httpMethodInterface = Class.forName(ORG_APACHE_COMMONS_HTTPCLIENT_HTTP_METHOD, true, httpMethodLoader);
                httpURI = Class.forName(ORG_APACHE_COMMONS_HTTPCLIENT_URI, true, httpMethodLoader);
            } else {
                httpMethodInterface = Class.forName(ORG_APACHE_COMMONS_HTTPCLIENT_HTTP_METHOD, true,
                        Thread.currentThread().getContextClassLoader());
                httpURI = Class.forName(ORG_APACHE_COMMONS_HTTPCLIENT_URI, true,
                        Thread.currentThread().getContextClassLoader());
            }
            Method getURI = httpMethodInterface.getMethod(GET_URI);
            Object uri = getURI.invoke(httpMethod);

            Method getHost = httpURI.getMethod(GET_HOST);
            String host = (String) getHost.invoke(uri);

            Method getPath = httpURI.getMethod(GET_PATH);
            String path = (String) getPath.invoke(uri);

            parameters.add(host);
            parameters.add(path);

        } catch (Throwable e) {
            logger.log(LogLevel.WARN, ERROR_IN_GET_APACHE_COMMONS_HTTP_REQUEST_PARAMETERS, e,
                    ProcessorThread.class.getName());
        }

    }

    public static void getOkHttpRequestParameters(Object[] object, JSONArray parameters) {

        Object httpEngine = object[0];
        try {
            Method getRequest = httpEngine.getClass().getMethod(GET_REQUEST);
            Object request = getRequest.invoke(httpEngine);

            Field httpUrl = request.getClass().getDeclaredField(URL);
            httpUrl.setAccessible(true);
            Object httpUrlObj = httpUrl.get(request);

            Method getUrl = httpUrlObj.getClass().getMethod(URL);
            URL url = (URL) getUrl.invoke(httpUrlObj);

            parameters.add(url.getHost());
            parameters.add(url.getPath());

        } catch (Throwable e) {
            logger.log(LogLevel.WARN, ERROR_IN_GET_OK_HTTP_REQUEST_PARAMETERS, e, ProcessorThread.class.getName());
        }

    }

    private void getHSQLParameterValue(Object object, JSONArray parameters) {

        switch (this.sourceString) {
            case HSQL_V2_4:
                try {
                    Class<?> statementClass = Thread.currentThread().getContextClassLoader()
                            .loadClass(IAgentConstants.ORG_HSQLDB_STATEMENT);
                    Field sqlField = statementClass.getDeclaredField(IAgentConstants.SQL);
                    sqlField.setAccessible(true);
                    parameters.add((String) sqlField.get(object));
                } catch (Throwable e) {
                    logger.log(LogLevel.WARN, ERROR_IN_GET_HSQL_PARAMETER_VALUE_FOR_HSQL_V2_4, e,
                            ProcessorThread.class.getName());
                }
                return;
            case HSQL_V1_8_SESSION:
            case HSQL_V1_8_CONNECTION:
            case HSQL_V2_3_4_CLIENT_CONNECTION:
                try {
                    Field mainStringField = object.getClass().getDeclaredField(MAIN_STRING);
                    mainStringField.setAccessible(true);
                    String parameter = (String) mainStringField.get(object);
                    if (!StringUtils.isEmpty(parameter)) {
                        parameters.add(parameter);
                    } else {
                        // for batch processing
                        Method getNavigatorMethod = object.getClass().getDeclaredMethod(GET_NAVIGATOR);
                        getNavigatorMethod.setAccessible(true);
                        Object navigatorObj = getNavigatorMethod.invoke(object);

                        Method getSizeMethod = navigatorObj.getClass().getSuperclass().getDeclaredMethod(GET_SIZE);
                        getSizeMethod.setAccessible(true);
                        int size = (int) getSizeMethod.invoke(navigatorObj);

                        Method getDataMethod = navigatorObj.getClass().getDeclaredMethod(GET_DATA, int.class);
                        getDataMethod.setAccessible(true);
                        for (int i = 0; i < size; i++) {
                            Object[] dataObj = (Object[]) getDataMethod.invoke(navigatorObj, i);
                            for (int j = 0; j < dataObj.length; j++) {
                                if (dataObj[j] != null && dataObj[j] instanceof String) {
                                    if (!((String) dataObj[j]).isEmpty()) {
                                        parameters.add(dataObj[j]);
                                    }
                                }
                            }
                        }
                    }
                } catch (Throwable e) {
                    logger.log(LogLevel.WARN, ERROR_IN_GET_HSQL_PARAMETER_VALUE_FOR_HSQL_V1_8_V2_3_4, e,
                            ProcessorThread.class.getName());
                }
                return;
        }
    }

    private void getPSQLParameterValue(Object[] obj, JSONArray parameters) {
        String sql = IAgentConstants.EMPTY_STRING;
        if (obj.length >= 0) {
            sql = obj[0].toString();
        }
        if (obj.length >= 1) {
            Object simpleParameter = obj[1];
            Field paramValuesField;
            try {
                paramValuesField = simpleParameter.getClass().getDeclaredField(IAgentConstants.PARAMVALUES);
                paramValuesField.setAccessible(true);
                Object[] paramValues = (Object[]) paramValuesField.get(simpleParameter);
                List<Object> paramArray = new ArrayList<>();
                for (int i = 0; i < paramValues.length; i++) {
                    String param = mapper.writeValueAsString(paramValues[i]);
                    sql = sql.replaceFirst(IAgentConstants.PSQL_PARAMETER_REPLACEMENT, param);
                    paramArray.add(param);
                }
                parameters.add(sql);
                parameters.add(paramArray);
            } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException
                    | JsonProcessingException e) {
                logger.log(LogLevel.WARN, ERROR_IN_GET_PSQL_PARAMETER_VALUE, e, ProcessorThread.class.getName());
            }

        }
    }

    /**
     * Adds the Values passed to a MSSQL prepared statement into ParameterList.
     *
     * @param paramList  the param list
     * @param parameters the parameters
     * @throws NoSuchFieldException     the no such field exception
     * @throws SecurityException        the security exception
     * @throws IllegalArgumentException the illegal argument exception
     * @throws IllegalAccessException   the illegal access exception
     */
    @SuppressWarnings({UNCHECKED})
    private static void addParamValuesMSSQL(ArrayList<Object[]> paramList, JSONArray parameters)
            throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        for (Object[] outParams : paramList) {
            JSONArray params = new JSONArray();

            for (int counter = 0; counter < outParams.length; counter++) {
                Field param = outParams[counter].getClass().getDeclaredField(MSSQL_INPUT_DTV_FIELD);
                param.setAccessible(true);
                Object value = param.get(outParams[counter]);
                param = value.getClass().getDeclaredField(MSSQL_IMPL_FIELD);
                param.setAccessible(true);
                value = param.get(value);
                param = value.getClass().getDeclaredField(MSSQL_VALUE_FIELD);
                param.setAccessible(true);
                value = param.get(value);
                params.add(value.toString());
            }
            parameters.add(params.toString());
        }
    }

    private void generateEvent(JavaAgentEventBean intCodeResultBean) {

        if (VulnerabilityCaseType.FILE_OPERATION.getCaseType().equals(intCodeResultBean.getCaseType())) {
            assignUserModuleInfo(intCodeResultBean);
        }

        intCodeResultBean.setEventGenerationTime(System.currentTimeMillis());
        if (intCodeResultBean.getSourceMethod() != null && (intCodeResultBean.getSourceMethod()
                .equals(IAgentConstants.JAVA_NET_URLCLASSLOADER)
                || intCodeResultBean.getSourceMethod().equals(IAgentConstants.JAVA_NET_URLCLASSLOADER_NEWINSTANCE))) {
            try {
                JSONArray agentJarPaths = new JSONArray();
//				agentJarPaths.addAll(Agent.jarPathSet);
                JavaAgentDynamicPathBean dynamicJarPathBean = new JavaAgentDynamicPathBean(K2Instrumentator.APPLICATION_UUID,
                        System.getProperty(IAgentConstants.USER_DIR), agentJarPaths, intCodeResultBean.getParameters());
                EventSendPool.getInstance().sendEvent(dynamicJarPathBean.toString());
                K2Instrumentator.JA_HEALTH_CHECK.incrementEventSentCount();
            } catch (IllegalStateException e) {
                logger.log(LogLevel.INFO, DROPPING_DYNAMIC_JAR_PATH_BEAN_EVENT + intCodeResultBean.getId()
                        + DUE_TO_BUFFER_CAPACITY_REACHED, ProcessorThread.class.getName());
                K2Instrumentator.JA_HEALTH_CHECK.incrementDropCount();
            } catch (Throwable e) {
                logger.log(LogLevel.WARN, ERROR_IN_GENERATE_EVENT_WHILE_CREATING_JAVA_AGENT_DYNAMIC_PATH_BEAN, e,
                        ProcessorThread.class.getName());
            }
        } else {
            try {
//				logger.log(LogLevel.INFO, "Generating event : " + intCodeResultBean,
//						ProcessorThread.class.getName());
                intCodeResultBean.setHttpRequest(new HttpRequestBean(this.httpRequest));
//				logger.log(LogLevel.INFO,"Generating event1 : "+ intCodeResultBean, ProcessorThread.class.getName());
                if (intCodeResultBean.getCaseType().equals(VulnerabilityCaseType.HTTP_REQUEST.getCaseType())) {
                    boolean validationResult = partialSSRFValidator(intCodeResultBean);
                    if (!validationResult) {
                        K2Instrumentator.JA_HEALTH_CHECK.incrementDropCount();
                        return;
                    }
                }
                intCodeResultBean.getHttpRequest().clearRawRequest();
                EventSendPool.getInstance().sendEvent(intCodeResultBean.toString());
                K2Instrumentator.JA_HEALTH_CHECK.incrementEventSentCount();
//				logger.log(LogLevel.INFO,"publish event: " + intCodeResultBean, ProcessorThread.class.getName());
            } catch (IllegalStateException e) {
                logger.log(LogLevel.INFO,
                        DROPPING_EVENT + intCodeResultBean.getId() + DUE_TO_BUFFER_CAPACITY_REACHED,
                        ProcessorThread.class.getName());
                K2Instrumentator.JA_HEALTH_CHECK.incrementDropCount();
            } catch (Throwable e) {
                logger.log(LogLevel.WARN, ERROR_IN_GENERATE_EVENT_WHILE_CREATING_INT_CODE_RESULT_BEAN, e,
                        ProcessorThread.class.getName());
            }

        }
    }

    private void assignUserModuleInfo(JavaAgentEventBean intCodeResultBean) {
        HttpRequestBean httpRequestBean = this.httpRequest;
        String filePath = intCodeResultBean.getParameters().get(0).toString();
        if (httpRequestBean.getFileExist().containsKey(filePath)) {
            httpRequestBean.getFileExist().get(filePath).setBeanValues(intCodeResultBean.getSourceMethod(),
                    intCodeResultBean.getUserFileName(), intCodeResultBean.getUserMethodName(),
                    intCodeResultBean.getCurrentMethod(), intCodeResultBean.getLineNumber());
        }

    }

    private boolean partialSSRFValidator(JavaAgentEventBean intCodeResultBean) {

        String rawRequest = intCodeResultBean.getHttpRequest().getRawRequest();
        String host = intCodeResultBean.getParameters().get(0).toString();
        String path = intCodeResultBean.getParameters().get(1).toString();

        if (StringUtils.containsIgnoreCase(rawRequest, host) || StringUtils.containsIgnoreCase(rawRequest, path))
            return true;
        String urlDecoded;
        try {
            urlDecoded = URLDecoder.decode(rawRequest, StandardCharsets.UTF_8.toString());
            if (StringUtils.containsIgnoreCase(urlDecoded, host) || StringUtils.containsIgnoreCase(urlDecoded, path))
                return true;
        } catch (UnsupportedEncodingException e) {
            logger.log(LogLevel.WARN, ERROR_IN_PARTIAL_SSRF_VALIDATOR, e, ProcessorThread.class.getName());
        }
//		logger.log(Level.FINE, "Dropping SSRF event: {0}", intCodeResultBean);
        return false;
    }

}
