/*
 * Copyright 2014 brutusin.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.brutusin.instrumentation.logging;


import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_IDENTIFIER;
import static org.brutusin.instrumentation.logging.IAgentConstants.MYSQL_IDENTIFIER;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_IDENTIFIER;

import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_CURRENT_OBJECT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_BATCH_STATEMENT_BUFFER_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_SQL_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_CONNECTION_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_ACTIVE_CONNECTION_PROP_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_STATEMENT_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_USER_SQL_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_IN_OUT_PARAM_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_BATCH_PARAM_VALUES_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_SERVER_STATEMENT_CLASS;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_PREPARED_STATEMENT_CLASS;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_PREPARED_BATCH_STATEMENT_CLASS;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_STATEMENT_EXECUTE_CMD_CLASS;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_BATCH_STATEMENT_EXECUTE_CMD_CLASS;

import static org.brutusin.instrumentation.logging.IAgentConstants.MYSQL_PREPARED_STATEMENT;

import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_INPUT_DTV_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_IMPL_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MSSQL_VALUE_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_NAMESPACE_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_COMMAND_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_PAYLOAD_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_DELETE_REQUEST_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MOGNO_ELEMENT_DATA_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_FILTER_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_MULTIPLE_UPDATES_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_SINGLE_UPDATE_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_INSERT_REQUESTS_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_DOCUMENT_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_WRITE_REQUEST_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_FIELD_NAME_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_DELETE_CLASS_FRAGMENT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_UPDATE_CLASS_FRAGMENT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_FIND_AND_UPDATE_CLASS_FRAGMENT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_INSERT_CLASS_FRAGMENT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_FIND_CLASS_FRAGMENT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_COMMAND_CLASS_FRAGMENT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_WRITE_CLASS_FRAGMENT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_DISTINCT_CLASS_FRAGMENT;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_COLLECTION_WILDCARD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_COLLECTION_FIELD;
import static org.brutusin.instrumentation.logging.IAgentConstants.MONGO_COMMAND_NAME_FIELD;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.channels.Channels;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import org.brutusin.commons.json.spi.JsonCodec;
import org.brutusin.instrumentation.Agent;
import org.brutusin.instrumentation.Interceptor;

import com.k2.org.json.simple.JSONArray;
import com.k2.org.json.simple.JSONObject;
import com.k2.org.objectweb.asm.tree.ClassNode;
import com.k2.org.objectweb.asm.tree.MethodNode;

import jnr.unixsocket.UnixSocketAddress;
import jnr.unixsocket.UnixSocketChannel;

public class LoggingInterceptor extends Interceptor {

	private File rootFile;
	private static final Set<String> allClasses;
	private static final Map<String, List<String>> interceptMethod;
	private static final Pattern PATTERN;
	private static final Set<String> executorMethods;
	private static PrintWriter writer;
	private static UnixSocketChannel channel;
	private static Integer VMPID;
	private static final String applicationUUID;

	static {
		applicationUUID = UUID.randomUUID().toString();
		PATTERN = Pattern.compile(IAgentConstants.TRACE_REGEX);
		allClasses = new HashSet<String>(Arrays.asList(IAgentConstants.ALL_CLASSES));
		executorMethods = new HashSet<String>(Arrays.asList(IAgentConstants.EXECUTORS));
		interceptMethod = new HashMap<String, List<String>>();
		for (int i = 0; i < IAgentConstants.ALL_METHODS.length; i++) {
			interceptMethod.put(IAgentConstants.ALL_CLASSES[i],
					new ArrayList<String>(Arrays.asList(IAgentConstants.ALL_METHODS[i])));
		}

	}

	public static String getContainerID() {

		File cgroupFile = new File("/proc/self/cgroup");
		if (!cgroupFile.isFile())
			return null;
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(cgroupFile));
		} catch (FileNotFoundException e) {
			return null;
		}

		String st;
		int index = -1;
		try {
			while ((st = br.readLine()) != null) {
				index = st.lastIndexOf("docker/");
				if (index > -1) {
					return st.substring(index + 7);
				}
				index = st.indexOf("kubepods/");
				if (index > -1) {
					return st.substring(st.lastIndexOf('/')+1);
				}
				// To support docker older versions
				index = st.lastIndexOf("lxc/");
				if (index > -1) {
					return st.substring(index + 4);
				}
			}

		} catch (IOException e) {
			return null;
		} finally {
			try {
				br.close();
			} catch (IOException e) {
			}
		}
		return null;
	}


    /**
     * Method to poll for Agent.getJarPathResultExecutorService to complete jarPathSet population & then create & send
     * desired JarPathBean .
     */
    public static void getJarPath() {
        Runnable jarPathPool = new Runnable() {
            public void run() {
                    System.out.println("Pooling getJarPathResultExecutorService to fetch results.");
                try {
                    if(Agent.getJarPathResultExecutorService.awaitTermination(5, TimeUnit.MINUTES)) {
                        if(!Agent.jarPathSet.isEmpty()){
                            JarPathBean jarPathBean = new JarPathBean(applicationUUID, new ArrayList<String>(Agent.jarPathSet));
                            writer.println(jarPathBean.toString());
                            writer.flush();
                            System.out.println("getJarPathResultExecutorService result fetched successfully.");
                        } else {
                            System.err.println("getJarPathResultExecutorService result is empty.");
                        }
                    } else {
                        System.err.println("Timeout reached waiting for getJarPathResultExecutorService.");
                    }
                } catch (InterruptedException e) {
                    System.err.println("Error occured while waiting for getJarPathResultExecutorService.");
                    e.printStackTrace();
                }
            }
        };

        ScheduledExecutorService jarPathPoolExecutorService = Executors.newSingleThreadScheduledExecutor();
        jarPathPoolExecutorService.schedule(jarPathPool, 240, TimeUnit.SECONDS);
        jarPathPoolExecutorService.shutdown();
    }

	@Override
	public void  init(String arg) throws Exception {
		this.rootFile = new File("/tmp/K2-instrumentation-logging/events.sock");
		if (!rootFile.exists()) {
			throw new RuntimeException("Root doesn't exists, Please start the K2-IntCode Agent");
		}
		try {
			UnixSocketAddress address = new UnixSocketAddress(this.rootFile);
			channel = UnixSocketChannel.open(address);
			writer = new PrintWriter(Channels.newOutputStream(channel));
			System.out.println("Connection to " + channel.getLocalAddress() + ", established successfully!!!");
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
		try {
            getJarPath();
		    RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
    		String runningVM = runtimeMXBean.getName();
			VMPID = Integer.parseInt(runningVM.substring(0, runningVM.indexOf('@')));
			ApplicationInfoBean applicationInfoBean = new ApplicationInfoBean(VMPID, applicationUUID);
			String containerId = getContainerID();
			String cmdLine = getCmdLineArgsByProc(VMPID);
			List<String> cmdlineArgs = Arrays.asList(cmdLine.split("\000"));
			if (containerId != null) {
				applicationInfoBean.setContainerID(containerId);
				applicationInfoBean.setIsHost(false);
			} else
				applicationInfoBean.setIsHost(true);
//			applicationInfoBean.setJvmArguments(new JSONArray(runtimeMXBean.getInputArguments()));
			applicationInfoBean.setJvmArguments(new JSONArray(cmdlineArgs));
			writer.println(applicationInfoBean.toString());
			writer.flush();


		} catch (Exception e) {
			
		}
	}

	private String getCmdLineArgsByProc(Integer pid) {
		File cmdlineFile = new File("/proc/" + pid + "/cmdline");
		if (!cmdlineFile.isFile())
			return null;
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(cmdlineFile));
			String cmdline = br.readLine();
			if (!cmdline.isEmpty())
				return cmdline;
		} catch (IOException e) {
		} finally {
			try {
				br.close();
			} catch (IOException e) {
			}
		}
		return null;
	}

	@Override
	public boolean interceptClass(String className, byte[] byteCode) {
		return allClasses.contains(className);
	}

	@Override
	public boolean interceptMethod(ClassNode cn, MethodNode mn) {
		// if (cn.name.equals("java/io/File"))
		// System.out.println("name: " + mn.name + " : " +
		// interceptMethod.get(cn.name).contains(mn.name));
		return interceptMethod.get(cn.name).contains(mn.name);
	}

	@SuppressWarnings({ "rawtypes" })
	@Override
	protected void doOnStart(Object source, Object[] arg, String executionId) {
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

			IntCodeResultBean intCodeResultBean = new IntCodeResultBean(start, sourceString, VMPID, applicationUUID);

			String klassName = null;
			
			
			
			
			// String methodName = null;
			StackTraceElement[] trace = Thread.currentThread().getStackTrace();
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

	private void generateEvent(IntCodeResultBean intCodeResultBean) {
		// trace(logFile, intCodeInterceptedResult.toString());
		System.out.println("publish event: " + intCodeResultBean);
		if (!channel.isConnected()) {
			System.out.println("try re connect");
			if (!rootFile.exists()) {
				throw new RuntimeException("Root doesn't exists, Please start the K2-IntCode Agent");
			}
			try {
				UnixSocketAddress address = new UnixSocketAddress(this.rootFile);
				channel.connect(address);
				writer = new PrintWriter(Channels.newOutputStream(channel));
				System.out.println("K2 UDSServer Connection restablished!!!");
			} catch (IOException e) {
				throw new RuntimeException(e.getMessage());
			}
		}
		intCodeResultBean.setEventGenerationTime(System.currentTimeMillis());
		writer.println(intCodeResultBean.toString());
		writer.flush();
	}

	@Override
	protected void doOnThrowableThrown(Object source, Throwable throwable, String executionId) {
	}

	@Override
	protected void doOnThrowableUncatched(Object source, Throwable throwable, String executionId) {
	}

	@Override
	protected void doOnFinish(Object source, Object result, String executionId) {
//		String sourceString = null;
//		Method m = null;
//		if (source instanceof Method) {
//			m = (Method) source;
//			sourceString = m.toGenericString();
//		}
//
//		if (IAgentConstants.MSSQL_EXECUTOR.equals(sourceString)) {
//			String klassName;
//			StackTraceElement[] trace = Thread.currentThread().getStackTrace();
//			IntCodeResultBean intCodeResultBean = (IntCodeResultBean) intCodeInterceptedResult.get(0);
//			for (int i = 0; i < trace.length; i++) {
//				klassName = trace[i].getClassName();
//				if (!PATTERN.matcher(klassName).matches()) {
//					intCodeResultBean.setUserAPIInfo(trace[i].getLineNumber(), klassName, trace[i].getMethodName());
//					if (i > 0)
//						intCodeResultBean.setCurrentMethod(trace[i - 1].getMethodName());
//					break;
//				}
//			}
//			intCodeInterceptedResult.remove(0);
//			generateEvent(intCodeResultBean);
//		}
	}

	@SuppressWarnings("unused")
	private static void trace(File f, String s) {
		if (s == null) {
			return;
		}
		try {
			FileOutputStream fos = new FileOutputStream(f, true);
			try {
				fos.write(s.getBytes());
				fos.write("\n".getBytes());
			} finally {
				fos.close();
			}
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
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
					childField = child.getClass().getSuperclass().getSuperclass().getDeclaredField(MSSQL_IN_OUT_PARAM_FIELD);
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
	 * @param args the arguments of Instrumented Method
	 * @param parameters the parameters
	 * @return the my SQL parameter value
	 */
	@SuppressWarnings("unchecked")
	private static void getMySQLParameterValue(Object[] args, JSONArray parameters) {
		for (Object obj : args) {
			if(obj.getClass().getName().contains(MYSQL_PREPARED_STATEMENT)) {
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
				JSONArray params =  new JSONArray();
				getMySQLParameterValue((Object[]) obj,params);
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
	 * @param args the arguments of Instrumented Method
	 * @param parameters the parameters
	 * @return the my SQL parameter value
	 * @throws NoSuchFieldException the no such field exception
	 * @throws SecurityException the security exception
	 * @throws IllegalArgumentException the illegal argument exception
	 * @throws IllegalAccessException the illegal access exception
	 */
	@SuppressWarnings("unchecked")
	public static void getMongoParameterValue(Object[] args, JSONArray parameters) throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
		Object protocol = args[0];		
		
		String namespace = null; 
		Field f = null;
		
		
		Class<? extends Object> nsClass = protocol.getClass();
		int depth = 0;
		String keyspaceName = null;
		
		JSONObject queryDetailObj = new JSONObject();
		// for getting the namespace 
		while (namespace == null && nsClass != null && depth<4) {
			try {
				f = nsClass.getDeclaredField(MONGO_NAMESPACE_FIELD);
				f.setAccessible(true);
				Object ns = f.get(protocol);
				namespace = ns.toString();
				
				queryDetailObj.put(MONGO_NAMESPACE_FIELD,namespace);
				keyspaceName = namespace.split("[.]")[1];
				if(!keyspaceName.equals(MONGO_COLLECTION_WILDCARD)) {
					queryDetailObj.put(MONGO_COLLECTION_FIELD,keyspaceName);
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
			if(payload != null ) {
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
				
				for(Object obj : deleteRequests) {
					try {
						f = obj.getClass().getDeclaredField(MOGNO_ELEMENT_DATA_FIELD);
						f.setAccessible(true);
						Object[] elementData = (Object[]) f.get(obj);
						
						for(Object request : elementData) {
							if( request!=null ) {
								f = request.getClass().getDeclaredField(MONGO_FILTER_FIELD);
								f.setAccessible(true);
								Object filter = f.get(request);
								parameters.add(filter.toString());
							}
						}
						
						
					}catch (NoSuchFieldException synchedDelete) {
						f = obj.getClass().getDeclaredField(MONGO_FILTER_FIELD);
						f.setAccessible(true);
						Object filter = f.get(obj);
						parameters.add(filter.toString());
					}
					
				}
			} else if (protocol.getClass().getName().contains(MONGO_UPDATE_CLASS_FRAGMENT)) {
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_UPDATE_CLASS_FRAGMENT.toLowerCase());
				List<Object> updates =  null;
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
			} else if (protocol.getClass().getName().contains(MONGO_INSERT_CLASS_FRAGMENT)){
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_INSERT_CLASS_FRAGMENT.toLowerCase());

				f = protocol.getClass().getDeclaredField(MONGO_INSERT_REQUESTS_FIELD);
				f.setAccessible(true);
				List<Object> insertRequests = (List<Object>) f.get(protocol);
				for(Object request : insertRequests) {
					f = request.getClass().getDeclaredField(MONGO_DOCUMENT_FIELD);
					f.setAccessible(true);
					Object document = f.get(request);
					parameters.add(document.toString());
				}
				
			} else if (protocol.getClass().getName().contains(MONGO_FIND_CLASS_FRAGMENT)){
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_FIND_CLASS_FRAGMENT.toLowerCase());

				f = protocol.getClass().getDeclaredField(MONGO_FILTER_FIELD);
				f.setAccessible(true);
				Object filter = f.get(protocol);
				parameters.add(filter.toString());
				
			} else if (protocol.getClass().getName().contains(MONGO_WRITE_CLASS_FRAGMENT)){
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_WRITE_CLASS_FRAGMENT.toLowerCase());

				f = protocol.getClass().getDeclaredField(MONGO_WRITE_REQUEST_FIELD);
				f.setAccessible(true);
				List<Object> writeRequests = (List<Object>) f.get(protocol);
				
				
				
				for(Object request : writeRequests) {
					
					if(request.getClass().getName().contains(MONGO_UPDATE_CLASS_FRAGMENT)) {
					f = request.getClass().getDeclaredField(MONGO_SINGLE_UPDATE_FIELD);
					f.setAccessible(true);
					Object update = f.get(request);
					parameters.add(update.toString());
					f = request.getClass().getDeclaredField(MONGO_FILTER_FIELD);
					f.setAccessible(true);
					Object filter = f.get(request);
					parameters.add(filter.toString());
					
					
					parameters.add(update.toString());
					} else if(request.getClass().getName().contains(MONGO_DELETE_CLASS_FRAGMENT)) {
						f = request.getClass().getDeclaredField(MONGO_FILTER_FIELD);
						f.setAccessible(true);
						Object filter = f.get(request);
						parameters.add(filter.toString());
						
					}else {
						f = request.getClass().getDeclaredField(MONGO_DOCUMENT_FIELD);
						f.setAccessible(true);
						Object document = f.get(request);
						parameters.add(document.toString());
						
					}
					
				}
				
			}  else if (protocol.getClass().getName().contains(MONGO_DISTINCT_CLASS_FRAGMENT)){
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_DISTINCT_CLASS_FRAGMENT.toLowerCase());

				f = protocol.getClass().getDeclaredField(MONGO_FIELD_NAME_FIELD);
				f.setAccessible(true);
				Object fieldName =  f.get(protocol);
				parameters.add(fieldName.toString());
				f = protocol.getClass().getDeclaredField(MONGO_FILTER_FIELD);
				f.setAccessible(true);
				Object filter =  f.get(protocol);
				parameters.add(filter.toString());
				
			} else if(protocol.getClass().getName().contains(MONGO_COMMAND_CLASS_FRAGMENT)) {
				queryDetailObj.put(MONGO_COMMAND_NAME_FIELD, MONGO_COMMAND_CLASS_FRAGMENT.toLowerCase());

				f = protocol.getClass().getDeclaredField(MONGO_COMMAND_FIELD);
				f.setAccessible(true);
				Object insertRequests = f.get(protocol);
				parameters.add(insertRequests.toString());
			} else {
				
				System.out.println(protocol.getClass().getName());
				
			}
			
		}
		// add Query Details
		parameters.add(queryDetailObj.toString());
	}
		
		
	
	
	/**
	 * This method is used to extract All the required parameters through the
	 * arguments of instrumented method
	 * 
	 * @param obj the obj
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
}
