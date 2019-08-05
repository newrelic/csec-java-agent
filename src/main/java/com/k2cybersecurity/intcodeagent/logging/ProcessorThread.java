package com.k2cybersecurity.intcodeagent.logging;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.APACHE_HTTP_REQUEST_EXECUTOR_METHOD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_LOADER_IDENTIFIER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.EXECUTORS;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.HSQL_V1_8_CONNECTION;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.HSQL_V1_8_SESSION;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.HSQL_V2_4;
//import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.JAVA_OPEN_CONNECTION_METHOD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.JAVA_OPEN_CONNECTION_METHOD2;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.JAVA_OPEN_CONNECTION_METHOD2_HTTPS;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.JAVA_OPEN_CONNECTION_METHOD2_HTTPS_2;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_ASYNC_METHOD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_METHOD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MOGNO_ELEMENT_DATA_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_COLLECTION_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_COLLECTION_WILDCARD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_COMMAND_CLASS_FRAGMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_COMMAND_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_COMMAND_NAME_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_DELETE_CLASS_FRAGMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_DELETE_REQUEST_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_DISTINCT_CLASS_FRAGMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_DOCUMENT_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_EXECUTORS;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_FIELD_NAME_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_FILTER_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_FIND_AND_UPDATE_CLASS_FRAGMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_FIND_CLASS_FRAGMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_IDENTIFIER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_INSERT_CLASS_FRAGMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_INSERT_REQUESTS_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_MULTIPLE_UPDATES_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_NAMESPACE_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_PAYLOAD_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_SINGLE_UPDATE_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_UPDATE_CLASS_FRAGMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_WRITE_CLASS_FRAGMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MONGO_WRITE_REQUEST_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_ACTIVE_CONNECTION_PROP_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_BATCH_PARAM_VALUES_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_BATCH_STATEMENT_BUFFER_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_BATCH_STATEMENT_EXECUTE_CMD_CLASS;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_CONNECTION_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_CURRENT_OBJECT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_IDENTIFIER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_IMPL_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_INPUT_DTV_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_IN_OUT_PARAM_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_PREPARED_BATCH_STATEMENT_CLASS;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_PREPARED_STATEMENT_CLASS;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_SERVER_STATEMENT_CLASS;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_SQL_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_STATEMENT_EXECUTE_CMD_CLASS;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_STATEMENT_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_USER_SQL_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MSSQL_VALUE_FIELD;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_IDENTIFIER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.ORACLE_CONNECTION_IDENTIFIER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.ORACLE_DB_IDENTIFIER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.ORACLE_STATEMENT_CLASS_IDENTIFIER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.PSQL42_EXECUTOR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.PSQLV2_EXECUTOR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.PSQLV3_EXECUTOR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.PSQLV3_EXECUTOR7_4;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
//import org.brutusin.commons.json.spi.JsonCodec;
import org.brutusin.instrumentation.Agent;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.k2cybersecurity.intcodeagent.models.javaagent.JavaAgentDynamicPathBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.JavaAgentEventBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.ServletInfo;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;

public class ProcessorThread implements Runnable {

	private static final Pattern PATTERN;
	private static Logger logger;
	private Object source;
	private Object[] arg;
	private Integer executionId;
	private StackTraceElement[] stackTrace;
	private Long threadId;
	private String sourceString;
	private ObjectMapper mapper;
	private JSONParser parser;
	private Long preProcessingTime;

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
	 * @param servletInfo
	 */

	public ProcessorThread(Object source, Object[] arg, Integer executionId, StackTraceElement[] stackTrace, long tId,
			String sourceString, long preProcessingTime) {
		this.source = source;
		this.arg = arg;
		this.executionId = executionId;
		this.stackTrace = stackTrace;
		this.threadId = tId;
		this.sourceString = sourceString;
		this.mapper = new ObjectMapper();
		this.parser = new JSONParser();
		this.preProcessingTime = preProcessingTime;
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
	public Integer getExecutionId() {
		return executionId;
	}

	/**
	 * @param executionId the executionId to set
	 */
	public void setExecutionId(Integer executionId) {
		this.executionId = executionId;
	}

	@Override
	public void run() {
		try {
			if (EXECUTORS.containsKey(sourceString)) {
				long start = System.currentTimeMillis();

				JavaAgentEventBean intCodeResultBean = new JavaAgentEventBean(start, preProcessingTime, sourceString,
						LoggingInterceptor.VMPID, LoggingInterceptor.applicationUUID,
						this.threadId + IAgentConstants.COLON_SEPERATOR + this.executionId,
						EXECUTORS.get(sourceString));

				String klassName = null;
				if (MONGO_EXECUTORS.containsKey(sourceString)) {
					intCodeResultBean.setValidationBypass(true);
				}

				// String methodName = null;
//				List<TraceElement> stackTrace = new ArrayList<>();
//				intCodeResultBean.setStacktrace(stackTrace);
				StackTraceElement[] trace = this.stackTrace;

//				for (int i = 0; i < trace.length; i++) {
//					TraceElement traceEntry = new TraceElement();
//					stackTrace.add(traceEntry);
//					traceEntry.setClassName(trace[i].getClassName());
//					traceEntry.setMethodName(trace[i].getMethodName());
//					traceEntry.setLineNumber(trace[i].getLineNumber());
//					klassName = traceEntry.getClassName();
//					if (IAgentConstants.MYSQL_GET_CONNECTION_MAP.containsKey(klassName)
//							&& IAgentConstants.MYSQL_GET_CONNECTION_MAP.get(klassName)
//									.contains(trace[i].getMethodName())) {
//						intCodeResultBean.setValidationBypass(true);
//					}
//				}

				if (IAgentConstants.FILE_OPEN_EXECUTORS.contains(sourceString)) {
					boolean javaIoFile = false;
					for (int i = 0; i < trace.length; i++) {
						klassName = trace[i].getClassName();
						if (javaIoFile) {
							if (!PATTERN.matcher(klassName).matches()) {
								intCodeResultBean.setParameters(toString(arg, sourceString));
								intCodeResultBean.setUserAPIInfo(trace[i].getLineNumber(), klassName,
										trace[i].getMethodName());
								if (i > 0)
									intCodeResultBean.setCurrentMethod(trace[i - 1].getMethodName());
							}
							if (intCodeResultBean.getUserClassName() != null
									&& !intCodeResultBean.getUserClassName().isEmpty()) {
//								logger.log(Level.FINE,"result bean : "+intCodeResultBean);
								generateEvent(intCodeResultBean);
							}
							logger.log(Level.FINE, "breaking");
							break;
						}
						if (klassName.equals(IAgentConstants.JAVA_IO_FILE)) {
//							logger.log(Level.FINE,"javaio found");
//							logger.log(Level.FINE,"next class : "+trace[i+1]);
							javaIoFile = true;
						}
					}
//					ServletEventPool.getInstance().decrementServletInfoReference(threadId, executionId, true);
					return;
				}

				for (int i = 0; i < trace.length; i++) {
					klassName = trace[i].getClassName();
					System.out.println(klassName);
					// if (klassName.equals(MSSQL_PREPARED_STATEMENT_CLASS)
					// || klassName.equals(MSSQL_PREPARED_BATCH_STATEMENT_CLASS)
					// || klassName.contains(MYSQL_PREPARED_STATEMENT)) {
					// intCodeResultBean.setValidationBypass(true);
					// } else
					if (IAgentConstants.MYSQL_GET_CONNECTION_MAP.containsKey(klassName)
							&& IAgentConstants.MYSQL_GET_CONNECTION_MAP.get(klassName)
									.contains(trace[i].getMethodName())) {
						intCodeResultBean.setValidationBypass(true);
						return;
					}
					if (!PATTERN.matcher(klassName).matches()) {
						JSONArray params = toString(arg, sourceString);
						if (params != null) {
							intCodeResultBean.setParameters(params);
							intCodeResultBean.setUserAPIInfo(trace[i].getLineNumber(), klassName,
									trace[i].getMethodName());
							if (i > 0)
								intCodeResultBean.setCurrentMethod(trace[i - 1].getMethodName());
						} else {
//							ServletEventPool.getInstance().decrementServletInfoReference(threadId, executionId, true);
							return;
						}
						break;
					}
				}
				if (intCodeResultBean.getUserClassName() != null && !intCodeResultBean.getUserClassName().isEmpty()) {
					generateEvent(intCodeResultBean);
				} else if (IAgentConstants.SYSYTEM_CALL_START.equals(sourceString)) {
					int traceId = getClassNameForSysytemCallStart(trace, intCodeResultBean);
					intCodeResultBean.setUserAPIInfo(trace[traceId].getLineNumber(), klassName,
							trace[traceId].getMethodName());
					intCodeResultBean.setParameters(toString(arg, sourceString));
					if (traceId > 0)
						intCodeResultBean.setCurrentMethod(trace[traceId - 1].getMethodName());
					generateEvent(intCodeResultBean);
				}
			}
		} catch (Exception e) {
			logger.log(Level.WARNING, "Error in run: {0}", e);
		} finally {
			ServletEventPool.getInstance().decrementServletInfoReference(threadId, executionId, true);
		}
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
	@SuppressWarnings("unchecked")
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
	@SuppressWarnings("unchecked")
	private void getMySQLParameterValue(Object[] args, JSONArray parameters, String sourceString) {
		try {
			int sqlObjectLocation = 1;
			int thisPointerLocation = args.length - 1;
			if (args[thisPointerLocation].getClass().getName().equals(String.class.getName())) {
				sqlObjectLocation = thisPointerLocation;
			}
			parameters.add(String.valueOf(arg[sqlObjectLocation]));

		} catch (Exception e) {
			logger.log(Level.WARNING, "Error in getMySQLParameterValue: {0}", e);
		}
	}

	/**
	 * Gets the mongo parameters.
	 *
	 * @param args       the arguments of Instrumented Method
	 * @param parameters the parameters
	 * @return the my SQL parameter value
	 * @throws NoSuchFieldException     the no such field exception
	 * @throws SecurityException        the security exception
	 * @throws IllegalArgumentException the illegal argument exception
	 * @throws IllegalAccessException   the illegal access exception
	 */
	@SuppressWarnings("unchecked")
	public static void getMongoParameterValue(Object[] args, JSONArray parameters)
			throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
		Object protocol = args[0];

		String namespace = null;
		Field f = null;

		Class<? extends Object> nsClass = protocol.getClass();
		int depth = 0;
		String keyspaceName = null;

		JSONObject queryDetailObj = new JSONObject();
		// for getting the namespace
		while (namespace == null && nsClass != null && depth < 4) {
			try {
				f = nsClass.getDeclaredField(MONGO_NAMESPACE_FIELD);
				f.setAccessible(true);
				Object ns = f.get(protocol);
				namespace = ns.toString();

				queryDetailObj.put(MONGO_NAMESPACE_FIELD, namespace);
				keyspaceName = namespace.split(IAgentConstants.DOTINSQUAREBRACKET)[1];
				if (!keyspaceName.equals(MONGO_COLLECTION_WILDCARD)) {
					queryDetailObj.put(MONGO_COLLECTION_FIELD, keyspaceName);
				}

			} catch (Exception ex) {
				nsClass = nsClass.getSuperclass();
				depth++;
			}
		}

		// for Connecter v 6.0 and above
		try {

			f = protocol.getClass().getDeclaredField(MONGO_COMMAND_FIELD);
			f.setAccessible(true);
			Object command = f.get(protocol);
			parameters.add(command.toString());
			f = protocol.getClass().getDeclaredField(MONGO_PAYLOAD_FIELD);
			f.setAccessible(true);
			Object payload = f.get(protocol);
			if (payload != null) {
				f = payload.getClass().getDeclaredField(MONGO_PAYLOAD_FIELD);
				f.setAccessible(true);
				payload = f.get(payload);
				parameters.add(payload.toString());
			}
		} catch (Exception e) {
			// for Connecter v 5.0 and below
			// fetch query parameters
			if (protocol.getClass().getName().contains(MONGO_DELETE_CLASS_FRAGMENT)) {
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_DELETE_CLASS_FRAGMENT.toLowerCase());
				f = protocol.getClass().getDeclaredField(MONGO_DELETE_REQUEST_FIELD);
				f.setAccessible(true);
				List<Object> deleteRequests = (List<Object>) f.get(protocol);

				for (Object obj : deleteRequests) {
					try {
						f = obj.getClass().getDeclaredField(MOGNO_ELEMENT_DATA_FIELD);
						f.setAccessible(true);
						Object[] elementData = (Object[]) f.get(obj);

						for (Object request : elementData) {
							if (request != null) {
								f = request.getClass().getDeclaredField(MONGO_FILTER_FIELD);
								f.setAccessible(true);
								Object filter = f.get(request);
								parameters.add(filter.toString());
							}
						}

					} catch (NoSuchFieldException synchedDelete) {
						f = obj.getClass().getDeclaredField(MONGO_FILTER_FIELD);
						f.setAccessible(true);
						Object filter = f.get(obj);
						parameters.add(filter.toString());
					}

				}
			} else if (protocol.getClass().getName().contains(MONGO_UPDATE_CLASS_FRAGMENT)) {
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_UPDATE_CLASS_FRAGMENT.toLowerCase());
				List<Object> updates = null;
				if (protocol.getClass().getName().contains(MONGO_FIND_AND_UPDATE_CLASS_FRAGMENT)) {
					updates = new ArrayList<Object>();
					updates.add(protocol);
				} else {
					f = protocol.getClass().getDeclaredField(MONGO_MULTIPLE_UPDATES_FIELD);
					f.setAccessible(true);
					updates = (List<Object>) f.get(protocol);
				}
				for (Object obj : updates) {
					f = obj.getClass().getDeclaredField(MONGO_FILTER_FIELD);
					f.setAccessible(true);
					Object filter = f.get(obj);
					parameters.add(filter.toString());
					f = obj.getClass().getDeclaredField(MONGO_SINGLE_UPDATE_FIELD);
					f.setAccessible(true);
					Object update = f.get(obj);
					parameters.add(update.toString());
				}
			} else if (protocol.getClass().getName().contains(MONGO_INSERT_CLASS_FRAGMENT)) {
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_INSERT_CLASS_FRAGMENT.toLowerCase());

				f = protocol.getClass().getDeclaredField(MONGO_INSERT_REQUESTS_FIELD);
				f.setAccessible(true);
				List<Object> insertRequests = (List<Object>) f.get(protocol);
				for (Object request : insertRequests) {
					f = request.getClass().getDeclaredField(MONGO_DOCUMENT_FIELD);
					f.setAccessible(true);
					Object document = f.get(request);
					parameters.add(document.toString());
				}

			} else if (protocol.getClass().getName().contains(MONGO_FIND_CLASS_FRAGMENT)) {
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_FIND_CLASS_FRAGMENT.toLowerCase());

				f = protocol.getClass().getDeclaredField(MONGO_FILTER_FIELD);
				f.setAccessible(true);
				Object filter = f.get(protocol);
				parameters.add(filter.toString());

			} else if (protocol.getClass().getName().contains(MONGO_WRITE_CLASS_FRAGMENT)) {
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_WRITE_CLASS_FRAGMENT.toLowerCase());

				f = protocol.getClass().getDeclaredField(MONGO_WRITE_REQUEST_FIELD);
				f.setAccessible(true);
				List<Object> writeRequests = (List<Object>) f.get(protocol);

				for (Object request : writeRequests) {

					if (request.getClass().getName().contains(MONGO_UPDATE_CLASS_FRAGMENT)) {
						f = request.getClass().getDeclaredField(MONGO_SINGLE_UPDATE_FIELD);
						f.setAccessible(true);
						Object update = f.get(request);
						parameters.add(update.toString());
						f = request.getClass().getDeclaredField(MONGO_FILTER_FIELD);
						f.setAccessible(true);
						Object filter = f.get(request);
						parameters.add(filter.toString());

						parameters.add(update.toString());
					} else if (request.getClass().getName().contains(MONGO_DELETE_CLASS_FRAGMENT)) {
						f = request.getClass().getDeclaredField(MONGO_FILTER_FIELD);
						f.setAccessible(true);
						Object filter = f.get(request);
						parameters.add(filter.toString());

					} else {
						f = request.getClass().getDeclaredField(MONGO_DOCUMENT_FIELD);
						f.setAccessible(true);
						Object document = f.get(request);
						parameters.add(document.toString());

					}

				}

			} else if (protocol.getClass().getName().contains(MONGO_DISTINCT_CLASS_FRAGMENT)) {
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_DISTINCT_CLASS_FRAGMENT.toLowerCase());

				f = protocol.getClass().getDeclaredField(MONGO_FIELD_NAME_FIELD);
				f.setAccessible(true);
				Object fieldName = f.get(protocol);
				parameters.add(fieldName.toString());
				f = protocol.getClass().getDeclaredField(MONGO_FILTER_FIELD);
				f.setAccessible(true);
				Object filter = f.get(protocol);
				parameters.add(filter.toString());

			} else if (protocol.getClass().getName().contains(MONGO_COMMAND_CLASS_FRAGMENT)) {
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_COMMAND_CLASS_FRAGMENT.toLowerCase());

				f = protocol.getClass().getDeclaredField(MONGO_COMMAND_FIELD);
				f.setAccessible(true);
				Object insertRequests = f.get(protocol);
				parameters.add(insertRequests.toString());
			} else {

//				logger.log(Level.FINE,protocol.getClass().getName());

			}

		}
		// add Query Details
		parameters.add(queryDetailObj.toString());
	}

	/**
	 * @param obj
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
			} catch (Exception e) {
			}
		}

	}

	/**
	 * 
	 * @param obj        this pointer object
	 * @param parameters
	 */
	private JSONArray getOracleParameterValue(Object thisPointer, JSONArray parameters, String sourceString) {

		Class<?> thisPointerClass = thisPointer.getClass();
		try {
			if (IAgentConstants.ORACLE_CLASS_SKIP_LIST.contains(thisPointerClass.getName())) {
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
		} catch (Exception e) {
			logger.log(Level.WARNING, "Error in getOracleParameterValue: {0}", e);
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
	@SuppressWarnings({ "unchecked", "unused" })
	private JSONArray toString(Object[] obj, String sourceString) {

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
				getMongoParameterValue(obj, parameters);
			} else if (obj[0] != null && sourceString.contains(ORACLE_DB_IDENTIFIER)) {
				parameters = getOracleParameterValue(arg[arg.length - 1], parameters, sourceString);
			} else if (obj[0] != null && sourceString.contains(CLASS_LOADER_IDENTIFIER)) {
				getClassLoaderParameterValue(obj, parameters);
			} else if (sourceString.equals(PSQLV3_EXECUTOR) || sourceString.equals(PSQLV2_EXECUTOR)
					|| sourceString.equals(PSQL42_EXECUTOR) || sourceString.equals(PSQLV3_EXECUTOR7_4)) {
				getPSQLParameterValue(obj, parameters);
			} else if (sourceString.equals(HSQL_V2_4) || sourceString.equals(HSQL_V1_8_CONNECTION)
					|| sourceString.equals(HSQL_V1_8_SESSION)) {
				getHSQLParameterValue(obj[0], parameters);
			} else if (sourceString.equals(APACHE_HTTP_REQUEST_EXECUTOR_METHOD)) {
				getApacheHttpRequestParameters(obj, parameters);
			} else if (sourceString.equals(JAVA_OPEN_CONNECTION_METHOD2)
					|| sourceString.equals(JAVA_OPEN_CONNECTION_METHOD2_HTTPS)
					|| sourceString.equals(JAVA_OPEN_CONNECTION_METHOD2_HTTPS_2)) {
				getJavaHttpRequestParameters(obj, parameters);
			} else if (sourceString.equals(JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_METHOD)
					|| sourceString.equals(JDK_INCUBATOR_MULTIEXCHANGE_RESONSE_ASYNC_METHOD)) {
				getJava9HttpClientParameters(obj, parameters);
			} else {
				for (int i = 0; i < obj.length; i++) {
					Object json = parser.parse(mapper.writeValueAsString(obj[i]));
					parameters.add(json);
				}
			}

		} catch (Throwable th) {
			parameters.add((obj != null) ? obj.toString() : null);
			logger.log(Level.WARNING, "Error in toString: {0}", th);
		}
		return parameters;
	}

	@SuppressWarnings("unchecked")
	private void getJavaHttpRequestParameters(Object[] obj, JSONArray parameters) {

		URL url = (URL) obj[0];
		parameters.add(url.getHost());
		parameters.add(url.getPath());

	}

	@SuppressWarnings("unchecked")
	private void getJava9HttpClientParameters(Object[] obj, JSONArray parameters) {
		Object multiExchangeObj = obj[0];
		try {

			Class<?> multiExchangeClass = Thread.currentThread().getContextClassLoader()
					.loadClass("jdk.incubator.http.MultiExchange");
			Field request = multiExchangeClass.getDeclaredField("request");
			request.setAccessible(true);
			Object httpReqObj = request.get(multiExchangeObj);

			Field uri = httpReqObj.getClass().getDeclaredField("uri");
			uri.setAccessible(true);
			URI uriObj = (URI) uri.get(httpReqObj);

			parameters.add(uriObj.getHost());
			parameters.add(uriObj.getPath());

		} catch (Exception e) {
			logger.log(Level.WARNING, "Error in getJava9HttpClientParameters : {0}", e);
		}
	}

	@SuppressWarnings("unchecked")
	private void getApacheHttpRequestParameters(Object[] object, JSONArray parameters) {

		Object request = object[0];
		Object httpContext = object[2];
		try {
			Class<?> httpClientInterface;
			Class<?> httpContextInterface;
			ClassLoader requestLoader = request.getClass().getClassLoader();
			ClassLoader httpContextLoader = httpContext.getClass().getClassLoader();
			if (requestLoader != null) {
				httpClientInterface = requestLoader.loadClass("org.apache.http.HttpRequest");
			} else {
				httpClientInterface = Thread.currentThread().getContextClassLoader()
						.loadClass("org.apache.http.HttpRequest");
			}

			if (httpContextLoader != null) {
				httpContextInterface = httpContextLoader.loadClass("org.apache.http.protocol.HttpContext");
			} else {
				httpContextInterface = Thread.currentThread().getContextClassLoader()
						.loadClass("org.apache.http.protocol.HttpContext");
			}

			Method getRequestLine = httpClientInterface.getMethod("getRequestLine");
			Object requestLine = getRequestLine.invoke(request);

			String requestLineStr = requestLine.toString();
			String[] requestLineTokens = requestLineStr.split("\\s+");
			String requestUri = requestLineTokens[1];

			Method getAttribute = httpContextInterface.getMethod("getAttribute", String.class);
			Object attributeHost = getAttribute.invoke(httpContext, "http.target_host");

			int indexOfQmark = requestUri.indexOf('?');
			// means request param is present
			String pathOnly = "";
			if (indexOfQmark != -1) {
				pathOnly = requestUri.substring(0, indexOfQmark);
			}

			parameters.add(attributeHost.toString());
			parameters.add(pathOnly);

		} catch (Exception e) {
			logger.log(Level.WARNING, "Error in getApacheHttpRequestParameters : {0}", e);
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
			} catch (Exception e) {
				logger.log(Level.WARNING, "Error in getHSQLParameterValue for HSQL_V2_4: {0}", e);
			}
			return;
		case HSQL_V1_8_SESSION:
		case HSQL_V1_8_CONNECTION:
			try {
				Field mainStringField = object.getClass().getDeclaredField("mainString");
				mainStringField.setAccessible(true);
				parameters.add((String) mainStringField.get(object));
			} catch (Exception e) {
				logger.log(Level.WARNING, "Error in getHSQLParameterValue for HSQL_V1_8_CONNECTION: {0}", e);
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
				logger.log(Level.WARNING, "Error in getPSQLParameterValue: {0}", e);
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
	@SuppressWarnings({ "unused", "unchecked" })
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
		intCodeResultBean.setEventGenerationTime(System.currentTimeMillis());
		if (intCodeResultBean.getSource() != null
				&& (intCodeResultBean.getSource().equals(IAgentConstants.JAVA_NET_URLCLASSLOADER)
						|| intCodeResultBean.getSource().equals(IAgentConstants.JAVA_NET_URLCLASSLOADER_NEWINSTANCE))) {
			try {
				List<String> list = (List<String>) intCodeResultBean.getParameters();

				JavaAgentDynamicPathBean dynamicJarPathBean = new JavaAgentDynamicPathBean(
						LoggingInterceptor.applicationUUID, System.getProperty(IAgentConstants.USER_DIR),
						new ArrayList<String>(Agent.jarPathSet), list);
				EventSendPool.getInstance().sendEvent(dynamicJarPathBean.toString());
			} catch (IllegalStateException e) {
				logger.log(Level.INFO, "Dropping dynamicJarPathBean event " + intCodeResultBean.getId()
						+ " due to buffer capacity reached");
				LoggingInterceptor.JA_HEALTH_CHECK.incrementDropCount();
			} catch (Exception e) {
				logger.log(Level.WARNING, "Error in generateEvent while creating JavaAgentDynamicPathBean: {0}", e);
			}
		} else {
			try {
				intCodeResultBean.setServletInfo(new ServletInfo(ExecutionMap.find(this.executionId,
						ServletEventPool.getInstance().getRequestMap().get(this.threadId))));
				if (intCodeResultBean.getCaseType().equals(VulnerabilityCaseType.HTTP_REQUEST.getCaseType())) {
					boolean validationResult = partialSSRFValidator(intCodeResultBean);
					if (!validationResult)
						return;
				}

				EventSendPool.getInstance().sendEvent(intCodeResultBean.toString());

//				logger.log(Level.INFO,"publish event: " + intCodeResultBean);
			} catch (IllegalStateException e) {
				logger.log(Level.INFO,
						"Dropping event " + intCodeResultBean.getId() + " due to buffer capacity reached.");
				LoggingInterceptor.JA_HEALTH_CHECK.incrementDropCount();
			} catch (Exception e) {
				logger.log(Level.WARNING, "Error in generateEvent while creating IntCodeResultBean: {0}", e);
			}

		}
	}

	private boolean partialSSRFValidator(JavaAgentEventBean intCodeResultBean) {

		String rawRequest = intCodeResultBean.getServletInfo().getRawRequest();
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
		}
		logger.log(Level.FINE, "Dropping SSRF event: {0}", intCodeResultBean);
		
		return false;
	}

	public static void setLogger() {
		ProcessorThread.logger = Logger.getLogger(ProcessorThread.class.getName());
	}
}
