package org.brutusin.instrumentation.logging;

import static org.brutusin.instrumentation.logging.IAgentConstants.MOGNO_ELEMENT_DATA_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_COLLECTION_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_COLLECTION_WILDCARD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_COMMAND_CLASS_FRAGMENT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_COMMAND_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_COMMAND_NAME_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_DELETE_CLASS_FRAGMENT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_DELETE_REQUEST_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_DISTINCT_CLASS_FRAGMENT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_DOCUMENT_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_FIELD_NAME_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_FILTER_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_FIND_AND_UPDATE_CLASS_FRAGMENT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_FIND_CLASS_FRAGMENT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_IDENTIFIER;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_INSERT_CLASS_FRAGMENT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_INSERT_REQUESTS_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_MULTIPLE_UPDATES_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_NAMESPACE_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_PAYLOAD_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_SINGLE_UPDATE_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_UPDATE_CLASS_FRAGMENT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_WRITE_CLASS_FRAGMENT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_WRITE_REQUEST_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_ACTIVE_CONNECTION_PROP_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_BATCH_PARAM_VALUES_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_BATCH_STATEMENT_BUFFER_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_BATCH_STATEMENT_EXECUTE_CMD_CLASS;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_CONNECTION_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_CURRENT_OBJECT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_IDENTIFIER;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_IMPL_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_INPUT_DTV_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_IN_OUT_PARAM_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_PREPARED_BATCH_STATEMENT_CLASS;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_PREPARED_STATEMENT_CLASS;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_SERVER_STATEMENT_CLASS;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_SQL_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_STATEMENT_EXECUTE_CMD_CLASS;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_STATEMENT_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_USER_SQL_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_VALUE_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MYSQL_IDENTIFIER;
import static org.brutusin.instrumentation.logging.IAgentConstants.MYSQL_PREPARED_STATEMENT;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

import org.brutusin.commons.json.spi.JsonCodec;

import com.k2.org.json.simple.JSONArray;
import com.k2.org.json.simple.JSONObject;

public class ProcessorThread implements Runnable {

	private static final Map<String, List<String>> interceptMethod;
	private static final Pattern PATTERN;
	private static final Set<String> executorMethods;

	static {
		PATTERN = Pattern.compile(IAgentConstants.TRACE_REGEX);
		executorMethods = new HashSet<String>(Arrays.asList(IAgentConstants.EXECUTORS));
		interceptMethod = new HashMap<String, List<String>>();
		for (int i = 0; i < IAgentConstants.ALL_METHODS.length; i++) {
			interceptMethod.put(IAgentConstants.ALL_CLASSES[i],
					new ArrayList<String>(Arrays.asList(IAgentConstants.ALL_METHODS[i])));
		}

	}
	private Object source;
	private Object[] arg;
	private String executionId;
	private StackTraceElement[] stackTrace;

	/**
	 * @param source
	 * @param arg
	 * @param executionId
	 * @param stackTrace
	 */
	public ProcessorThread(Object source, Object[] arg, String executionId, StackTraceElement[] stackTrace) {
		this.source = source;
		this.arg = arg;
		this.executionId = executionId;
		this.stackTrace = stackTrace;
	}

	/**
	 * @return the source
	 */
	public Object getSource() {
		return source;
	}

	/**
	 * @param source
	 *            the source to set
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
	 * @param arg
	 *            the arg to set
	 */
	public void setArg(Object[] arg) {
		this.arg = arg;
	}

	/**
	 * @return the executionId
	 */
	public String getExecutionId() {
		return executionId;
	}

	/**
	 * @param executionId
	 *            the executionId to set
	 */
	public void setExecutionId(String executionId) {
		this.executionId = executionId;
	}

	@Override
	public void run() {
		String sourceString = null;
		Method m = null;
		Constructor c = null;
		if (source instanceof Method) {
			m = (Method) source;
			sourceString = m.toGenericString();
			// System.out.println(m.toGenericString());
		} else if (source instanceof Constructor) {
			c = (Constructor) source;
			sourceString = c.toGenericString();
			// System.out.println(c.toGenericString());
		}
		// System.out.println(executorMethods.contains(sourceString)+"::executorMethods.contains(sourceString)\n"+sourceString);
		if (sourceString != null && executorMethods.contains(sourceString)) {
			long start = System.currentTimeMillis();
			// if (sourceString.equals(IAgentConstants.SYSYTEM_CALL_START)) {
			// System.out.println("Found : " + sourceString + "Param : " +
			// toString(arg));
			// StackTraceElement[] trace =
			// Thread.currentThread().getStackTrace();
			// for (int i = 0; i < trace.length; i++) {
			// System.err.println("\t" + trace[i].getClassName());
			// }
			// }
			// boolean fileExecute = false;
			// if(fileExecutors.contains(sourceString)) {
			// fileExecute = true;
			// }

			IntCodeResultBean intCodeResultBean = new IntCodeResultBean(start, sourceString, LoggingInterceptor.VMPID,
					LoggingInterceptor.applicationUUID);

			String klassName = null;

			// String methodName = null;
			StackTraceElement[] trace = this.stackTrace;
			for (int i = 0; i < trace.length; i++) {
				klassName = trace[i].getClassName();
				if (!PATTERN.matcher(klassName).matches()) {
					intCodeResultBean.setParameters(toString(arg));
					intCodeResultBean.setUserAPIInfo(trace[i].getLineNumber(), klassName, trace[i].getMethodName());
					if (i > 0)
						intCodeResultBean.setCurrentMethod(trace[i - 1].getMethodName());
					break;
				}
			}
			if (intCodeResultBean.getUserClassName() != null && !intCodeResultBean.getUserClassName().isEmpty()) {
				generateEvent(intCodeResultBean);
			} else if (IAgentConstants.SYSYTEM_CALL_START.equals(sourceString)) {
				int traceId = getClassNameForSysytemCallStart(trace, intCodeResultBean);
				intCodeResultBean.setUserAPIInfo(trace[traceId].getLineNumber(), klassName,
						trace[traceId].getMethodName());
				intCodeResultBean.setParameters(toString(arg));
				if (traceId > 0)
					intCodeResultBean.setCurrentMethod(trace[traceId - 1].getMethodName());
				generateEvent(intCodeResultBean);
			}

		}
	}

	private int getClassNameForSysytemCallStart(StackTraceElement[] trace, IntCodeResultBean intCodeResultBean) {
		boolean classRuntimeFound = false;
		for (int i = 0; i < trace.length; i++) {
			if (trace[i].getClassName().equals("java.lang.Runtime"))
				classRuntimeFound = true;
			else if (classRuntimeFound)
				return i;
		}
		return -1;
	}

	/**
	 * This method is used for MSSQL parameter Extraction
	 *
	 * @param obj
	 *            the object in argument of Instrumented Method
	 * @param parameters
	 *            the parameter list as a JSONArray
	 * @return void
	 * @throws NoSuchFieldException
	 *             the no such field exception
	 * @throws SecurityException
	 *             the security exception
	 * @throws IllegalArgumentException
	 *             the illegal argument exception
	 * @throws IllegalAccessException
	 *             the illegal access exception
	 */
	@SuppressWarnings("unchecked")
	private static void getParameterValue(Object obj, JSONArray parameters)
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
				// com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement42 is made instead of
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
					// com.microsoft.sqlserver.jdbc.SQLServerPreparedStatement42 is made instead of
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
			Field field = obj.getClass().getDeclaredField("sql");
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
	 * @param args
	 *            the arguments of Instrumented Method
	 * @param parameters
	 *            the parameters
	 * @return the my SQL parameter value
	 */
	@SuppressWarnings("unchecked")
	private static void getMySQLParameterValue(Object[] args, JSONArray parameters) {
		for (Object obj : args) {
			if (obj.getClass().getName().contains(MYSQL_PREPARED_STATEMENT)) {
				int start = obj.toString().indexOf(":");
				parameters.add(obj.toString().substring(0, start));
				parameters.add(obj.toString().substring(start + 1));

			} else if (obj instanceof byte[]) {
				try {
					String byteParam = new String((byte[]) obj, "UTF-8");
					parameters.add(byteParam.trim());
				} catch (UnsupportedEncodingException e) {
					e.printStackTrace();
				}
			} else if (obj instanceof Object[]) {
				JSONArray params = new JSONArray();
				getMySQLParameterValue((Object[]) obj, params);
				parameters.add(params);
			} else {
				try {
					parameters.add(JsonCodec.getInstance().transform(obj));
				} catch (Throwable e) {
					parameters.add(obj.toString());
				}
			}
		}

	}

	/**
	 * Gets the mongo parameters.
	 *
	 * @param args
	 *            the arguments of Instrumented Method
	 * @param parameters
	 *            the parameters
	 * @return the my SQL parameter value
	 * @throws NoSuchFieldException
	 *             the no such field exception
	 * @throws SecurityException
	 *             the security exception
	 * @throws IllegalArgumentException
	 *             the illegal argument exception
	 * @throws IllegalAccessException
	 *             the illegal access exception
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
				keyspaceName = namespace.split("[.]")[1];
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

				// System.out.println(protocol.getClass().getName());

			}

		}
		// add Query Details
		parameters.add(queryDetailObj.toString());
	}

	/**
	 * This method is used to extract All the required parameters through the
	 * arguments of instrumented method
	 * 
	 * @param obj
	 *            the obj
	 * @return the JSON array
	 */
	@SuppressWarnings({ "unchecked", "unused" })
	private static JSONArray toString(Object[] obj) {
		if (obj == null) {
			return null;
		}

		JSONArray parameters = new JSONArray();
		try {
			Object firstElement = obj[0];

			if (firstElement != null && firstElement.getClass() != null
					&& obj[0].getClass().getName().contains(MSSQL_IDENTIFIER)) {
				getParameterValue(obj[0], parameters);
			} else if (firstElement != null && firstElement.getClass().getName().contains(MYSQL_IDENTIFIER)) {
				getMySQLParameterValue(obj, parameters);
			} else if (firstElement != null && firstElement.getClass().getName().contains(MONGO_IDENTIFIER)) {
				getMongoParameterValue(obj, parameters);
			} else {
				for (int i = 0; i < obj.length; i++) {
					if (obj[i] instanceof byte[]) {
						try {
							String byteParam = new String((byte[]) obj[i], "UTF-8");
							parameters.add(byteParam.trim());
						} catch (UnsupportedEncodingException e) {
							e.printStackTrace();
						}
					} else if (obj[i] instanceof Object[]) {
						parameters.add(toString((Object[]) obj[i]));
					}
					// b.append(toString((Object[]) obj[i]));
					else

						parameters.add(JsonCodec.getInstance().transform(obj[i]));
					// b.append(JsonCodec.getInstance().transform(obj[i]));
					// if (i != obj.length - 1)
					// b.append(',');
				}
			}

		} catch (Throwable th) {
			parameters.add((obj != null) ? JsonCodec.getInstance().transform(obj.toString()) : null);
			// th.printStackTrace();
		}

		// StringBuilder b = new StringBuilder();
		// b.append('[');

		// b.append(']');
		// return b.toString();
		return parameters;
	}

	/**
	 * Adds the Values passed to a MSSQL prepared statement into ParameterList.
	 *
	 * @param paramList
	 *            the param list
	 * @param parameters
	 *            the parameters
	 * @throws NoSuchFieldException
	 *             the no such field exception
	 * @throws SecurityException
	 *             the security exception
	 * @throws IllegalArgumentException
	 *             the illegal argument exception
	 * @throws IllegalAccessException
	 *             the illegal access exception
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

	private void generateEvent(IntCodeResultBean intCodeResultBean) {
		// trace(logFile, intCodeInterceptedResult.toString());
		intCodeResultBean.setEventGenerationTime(System.currentTimeMillis());
		System.out.println("publish event: " + intCodeResultBean.getEventGenerationTime());
		EventThreadPool.getInstance().getEventBuffer().append(intCodeResultBean.toString());
		if (EventThreadPool.getInstance().getEventBuffer().toString().getBytes().length > 1024 * 50) {
			LoggingInterceptor.writer.println(intCodeResultBean.toString());
			LoggingInterceptor.writer.flush();
		}
	}

}
