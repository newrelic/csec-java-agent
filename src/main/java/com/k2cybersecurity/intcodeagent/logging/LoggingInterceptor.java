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
package com.k2cybersecurity.intcodeagent.logging;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.APPLICATION_INFO_POSTED_MSG;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.BYTE_BUFFER_FIELD_BUF;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.BYTE_BUFFER_FIELD_HB;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.BYTE_BUFFER_FIELD_LASTVALID;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.BYTE_BUFFER_FIELD_LIMIT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.BYTE_BUFFER_FIELD_POSITION;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CGROUP_FILE_NAME;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_COM_MICROSOFT_SQLSERVER_JDBC_SQL_SERVER_STATEMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_COM_MONGODB_ASYNC_CLIENT_ASYNC_OPERATION_EXECUTOR_IMPL;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_COM_MONGODB_ASYNC_CLIENT_MONGO_CLIENT_IMPL$2;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_COM_MONGODB_ASYNC_CLIENT_OPERATION_EXECUTOR_IMPL;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_COM_MONGODB_CONNECTION_DEFAULT_SERVER_CONNECTION;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_COM_MONGODB_INTERNAL_CONNECTION_DEFAULT_SERVER_CONNECTION;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_COM_MYSQL_CJ_MYSQLA_IO_MYSQLA_PROTOCOL;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_COM_MYSQL_CJ_NATIVE_SESSION;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_COM_MYSQL_JDBC_MYSQL_IO;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_COM_MYSQL_JDBC_SERVER_PREPARED_STATEMENT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_JAVA_LANG_PROCESS_IMPL;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_JAVA_NET_URL_CLASS_LOADER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_ORACLE_JDBC_DRIVER_T4CTT_IFUN;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_ORG_APACHE_CATALINA_CONNECTOR_COYOTE_ADAPTER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_ORG_APACHE_CATALINA_CONNECTOR_INPUT_BUFFER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_ORG_ECLIPSE_JETTY_HTTP_HTTP_PARSER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_ORG_ECLIPSE_JETTY_SERVER_HTTP_CONNECTION;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_ORG_HSQLDB_HSQL_CLIENT_CONNECTION;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_ORG_HSQLDB_SESSION;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_ORG_POSTGRESQL_CORE_V2_QUERY_EXECUTOR_IMPL;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CLASS_ORG_POSTGRESQL_CORE_V3_QUERY_EXECUTOR_IMPL;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CMD_LINE_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.COLON_SEPERATOR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.COYOTE_ABSTRACT_INPUT_BUFFER_CLASS_NAME;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.DIR_SEPERATOR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.DOCKER_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.HOST_IP_FOUND_MSG;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.HOST_PROP_FILE_NAME;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.INSTRUMENTED_METHODS;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.JA_CONNECT_SUCCESS_MSG;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.JETTY_PARSE_NEXT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.JETTY_REQUEST_ON_FILLABLE;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.K2_IC_TCP_PORT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.KUBEPODS_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.LXC_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_CONNECTOR_5_0_4_PREPARED_SOURCE;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_CONNECTOR_6_0_2_SOURCE;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_CONNECTOR_6_0_3_SOURCE;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_CONNECTOR_6_SOURCE;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_CONNECTOR_8_SOURCE;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_FIELD_ORIGINAL_SQL;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_FIELD_QUERY;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_PREPARED_QUERY_8;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_PREPARED_STATEMENT_4;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_PREPARED_STATEMENT_42;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_PREPARED_STATEMENT_5;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_PREPARED_STATEMENT_5_0_4;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_PREPARED_STATEMENT_6;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_PREPARED_STATEMENT_8;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_PREPARED_STATEMENT_SOURCE_8;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.MYSQL_SOURCE_METHOD_LIST;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.NEW_LINE_SEQUENCE;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.NULL_CHAR_AS_STRING;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.PROC_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.STAT;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.TOMCAT_7;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.TOMCAT_8;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.TOMCAT_9;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.TOMCAT_COYOTE_ADAPTER_SERVICE;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.TOMCAT_FIELD_SERVERNUMBER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.TOMCAT_REQUEST_FIELD_BYTEBUFFER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.TOMCAT_REQUEST_FIELD_INPUTBUFFER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.TOMCAT_SERVER_INFO_CLASS_NAME;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.TOMCAT_SETBYTEBUFFER;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.TOMCAT_VERSION_DETECTED_MSG;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.VERSION_SPLIT_EXPR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.VMPID_SPLIT_CHAR;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.brutusin.instrumentation.Agent;
import org.brutusin.instrumentation.Interceptor;
import org.json.simple.JSONArray;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import com.k2cybersecurity.intcodeagent.models.javaagent.ApplicationInfoBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.JAHealthCheck;
import com.k2cybersecurity.intcodeagent.models.javaagent.ServletInfo;
import com.k2cybersecurity.intcodeagent.models.javaagent.ShutDownEvent;

public class LoggingInterceptor extends Interceptor {

	private static final String SCOPE = ".scope";
	private static final String DOCKER_1_13 = "/docker-";
	private static final int SOCKET_CONNECT_TIMEOUT = 500;
	protected static Integer VMPID;
	protected static final String applicationUUID;
	public static ApplicationInfoBean APPLICATION_INFO_BEAN;
	protected static JAHealthCheck JA_HEALTH_CHECK;

	protected static Class<?> mysqlPreparedStatement8Class, mysqlPreparedStatement5Class, abstractInputBufferClass;
	protected static String tomcatVersion;
	protected static int tomcatMajorVersion;
	static final int MAX_DEPTH_LOOKUP = 4; // Max number of superclasses to lookup for a field
	// protected static Map<Long, ServletInfo> requestMap;
	public static String hostip = "";
	private static Logger logger;

	static {
		applicationUUID = Agent.APPLICATION_UUID;
	}

	public static String getContainerID() {

		File cgroupFile = new File(CGROUP_FILE_NAME);
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
				index = st.lastIndexOf(DOCKER_DIR);
				if (index > -1) {
					return st.substring(index + 7);
				}
				index = st.indexOf(KUBEPODS_DIR);
				if (index > -1) {
					return st.substring(st.lastIndexOf(DIR_SEPERATOR) + 1);
				}
				// To support docker older versions
				index = st.lastIndexOf(LXC_DIR);
				if (index > -1) {
					return st.substring(index + 4);
				}
				// docker version 1.13.1
				index = st.lastIndexOf(DOCKER_1_13);
				int indexEnd = st.lastIndexOf(SCOPE);
				if (index > -1 && indexEnd > -1) {
					return st.substring(index + 8, indexEnd);
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

	public static ApplicationInfoBean createApplicationInfoBean() {
		try {
			RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
			String runningVM = runtimeMXBean.getName();
			VMPID = Integer.parseInt(runningVM.substring(0, runningVM.indexOf(VMPID_SPLIT_CHAR)));
			ApplicationInfoBean applicationInfoBean = new ApplicationInfoBean(VMPID, applicationUUID);
			applicationInfoBean.setStartTime(runtimeMXBean.getStartTime());
			String containerId = getContainerID();
			String cmdLine = getCmdLineArgsByProc(VMPID);
			applicationInfoBean.setProcStartTime(getStartTimeByProc(VMPID));
			applicationInfoBean.setJvmArguments(cmdLine);
//			if (cmdLine != null) {
//				List<String> cmdlineArgs = Arrays.asList(cmdLine.split(NULL_CHAR_AS_STRING));
//				JSONArray jsonArray = new JSONArray();
//				jsonArray.addAll(cmdlineArgs);
//				applicationInfoBean.setJvmArguments(jsonArray);
//			}
			if (containerId != null) {
				applicationInfoBean.setContainerID(containerId);
				applicationInfoBean.setIsHost(false);
			} else
				applicationInfoBean.setIsHost(true);
			// applicationInfoBean.setJvmArguments(new
			// JSONArray(runtimeMXBean.getInputArguments()));
			return applicationInfoBean;
		} catch (Exception e) {
			logger.log(Level.WARNING, "Exception occured in createApplicationInfoBean: {0}", e);
		}
		return null;
	}

	synchronized protected static void connectSocket() {
		Socket socket = EventThreadPool.getInstance().getSocket();
		if (socket == null || !socket.isConnected() || socket.isClosed()) {
			try (BufferedReader reader = new BufferedReader(new FileReader(HOST_PROP_FILE_NAME))) {
				hostip = reader.readLine();
				if (hostip == null || hostip.isEmpty())
					throw new RuntimeException("Host ip not found");
				logger.log(Level.INFO, HOST_IP_FOUND_MSG + hostip);
				socket = new Socket();
				SocketAddress socketAddr = new InetSocketAddress(hostip, K2_IC_TCP_PORT);
				socket.connect(socketAddr, SOCKET_CONNECT_TIMEOUT);
				socket.setKeepAlive(true);
				EventThreadPool.getInstance().setSocket(socket);
				EventThreadPool.getInstance().setObjectStream(new ObjectOutputStream(socket.getOutputStream()));
			} catch (Exception e) {
				throw new RuntimeException("Can't connect to IC, agent installation failed.", e);
			}
			if (socket == null || !socket.isConnected() || socket.isClosed()) {
				throw new RuntimeException("Can't connect to IC, agent installation failed.");
			} else {
				logger.log(Level.INFO, JA_CONNECT_SUCCESS_MSG);
				logger.log(Level.INFO, APPLICATION_INFO_POSTED_MSG + LoggingInterceptor.APPLICATION_INFO_BEAN);
				EventThreadPool.getInstance().getEventQueue().add(LoggingInterceptor.APPLICATION_INFO_BEAN);
				Agent.allClassLoadersCount.set(0);
			}
		}
	}

	synchronized protected static void disconnectSocket() {
		try {
			EventThreadPool.getInstance().getObjectStream().flush();
			EventThreadPool.getInstance().getObjectStream().close();
			EventThreadPool.getInstance().getSocket().close();
		} catch (IOException e) {
			logger.severe(e.toString());
		}
	}

	@Override
	public void init(String arg) throws Exception {
		/*
		 * this.rootFile = new File("/tmp/K2-instrumentation-logging/events.sock"); if
		 * (!rootFile.exists()) { throw new
		 * RuntimeException("Root doesn't exists, Please start the K2-IntCode Agent"); }
		 * try { UnixSocketAddress address = new UnixSocketAddress(this.rootFile);
		 * channel = UnixSocketChannel.open(address); writer = new BufferedWriter(new
		 * OutputStreamWriter(Channels.newOutputStream(channel)));
		 * System.out.println("Connection to " + channel.getLocalAddress() +
		 * ", established successfully!!!"); } catch (IOException ex) { throw new
		 * RuntimeException(ex); }
		 */
//		try {
//			K2Native.k2init();
//		} catch (Exception e) {
//			logger.log(Level.WARNING,"Error loading k2JavaNative.so", e);
//		}
		
		ConfigK2Logs.getInstance().initializeLogs();
		APPLICATION_INFO_BEAN = createApplicationInfoBean();
		JA_HEALTH_CHECK = new JAHealthCheck(applicationUUID);
		try {
			connectSocket();
		} catch (Exception e) {
			logger.log(Level.WARNING, "Error occured while trying to connect to socket: {0}", e);
		}
		IPScheduledThread.getInstance();
		eventWritePool();
	}

	private static void eventWritePool() {

		try {
			EventThreadPool.getInstance().setEventPoolExecutor(Executors.newScheduledThreadPool(1));
			EventThreadPool.getInstance().getEventPoolExecutor()
					.scheduleWithFixedDelay(EventThreadPool.getInstance().getQueuePooler(), 1, 1, TimeUnit.SECONDS);
		} catch (Exception e) {
			logger.log(Level.WARNING, "Exception occured in eventWritePool: {0}", e);
		}
	}

	private static String getCmdLineArgsByProc(Integer pid) {
		File cmdlineFile = new File(PROC_DIR + pid + CMD_LINE_DIR);
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

	private static String getStartTimeByProc(Integer pid) {
		File statFile = new File(PROC_DIR + pid + STAT);
		if (!statFile.isFile())
			return null;
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(statFile));
			String statData = br.readLine();
			if (!statData.isEmpty()) {
				String[] statArray = statData.split("\\s+");
				if (statArray.length >= 21) {
					return statArray[21];
				}
			}
		} catch (IOException e) {
		} finally {
			try {
				br.close();
			} catch (IOException e) {
			}
		}
		return null;
	}

	private static String readByteBuffer(ByteBuffer buffer) {
		int currPos = buffer.position();
		StringBuffer stringBuffer = new StringBuffer();
		while (buffer.remaining() > 0) {
			stringBuffer.append((char) buffer.get());
		}
		buffer.position(currPos);
		return stringBuffer.toString();
	}

	@Override
	public boolean interceptClass(String className, byte[] byteCode) {
		// System.out.println("class came to instument : "+className);
		// if (className.startsWith("org/hsqldb/")) {
		// System.out.println("class to instument : "+className);
		// return true;
		// }

		return INSTRUMENTED_METHODS.containsKey(className);
	}

	public com.k2cybersecurity.intcodeagent.logging.ByteBuffer preProcessTomcatByteBuffer(byte[] buffer, int limitHb) {
		byte[] modifiedBuffer = new byte[limitHb];
		modifiedBuffer[0] = buffer[0];
		int k = 1;
		for (int i = 1; i < limitHb - 2; i++) {
			if (buffer[i + 1] == 13 && buffer[i + 2] == 10 && i + 4 <= limitHb && buffer[i + 3] == 13
					&& buffer[i + 4] == 10) {
				i++;
				while (i < limitHb) {
					modifiedBuffer[k] = buffer[i];
					i++;
					k++;
				}
				return new com.k2cybersecurity.intcodeagent.logging.ByteBuffer(modifiedBuffer, k);
			}
			if (buffer[i + 1] == 13 && buffer[i + 2] == 10 && buffer[i - 1] == buffer[i]) {

			} else {
				modifiedBuffer[k] = buffer[i];
				k++;
			}
		}
		modifiedBuffer[k++] = 13;
		modifiedBuffer[k++] = 10;
		return new com.k2cybersecurity.intcodeagent.logging.ByteBuffer(modifiedBuffer, k);
	}

	@Override
	public boolean interceptMethod(ClassNode cn, MethodNode mn) {

		switch (cn.name) {
		case CLASS_ORG_HSQLDB_HSQL_CLIENT_CONNECTION:
		case CLASS_ORG_HSQLDB_SESSION:
			if (INSTRUMENTED_METHODS.get(cn.name).contains(mn.name))
				JA_HEALTH_CHECK.getProtectedDB().add("HSQL");
			break;
		case CLASS_ORG_POSTGRESQL_CORE_V2_QUERY_EXECUTOR_IMPL:
		case CLASS_ORG_POSTGRESQL_CORE_V3_QUERY_EXECUTOR_IMPL:
			if (INSTRUMENTED_METHODS.get(cn.name).contains(mn.name))
				JA_HEALTH_CHECK.getProtectedDB().add("PSQL");
			break;
		case CLASS_ORG_ECLIPSE_JETTY_HTTP_HTTP_PARSER:
		case CLASS_ORG_ECLIPSE_JETTY_SERVER_HTTP_CONNECTION:
			if (INSTRUMENTED_METHODS.get(cn.name).contains(mn.name))
				JA_HEALTH_CHECK.setProtectedServer("JETTY");
			break;
		case CLASS_ORG_APACHE_CATALINA_CONNECTOR_INPUT_BUFFER:
		case CLASS_ORG_APACHE_CATALINA_CONNECTOR_COYOTE_ADAPTER:
			if (INSTRUMENTED_METHODS.get(cn.name).contains(mn.name))
				JA_HEALTH_CHECK.setProtectedServer("TOMCAT");
			break;
		case CLASS_ORACLE_JDBC_DRIVER_T4CTT_IFUN:
			if (INSTRUMENTED_METHODS.get(cn.name).contains(mn.name))
				JA_HEALTH_CHECK.getProtectedDB().add("ORACLE");
			break;
		case CLASS_JAVA_NET_URL_CLASS_LOADER:
			// if(INSTRUMENTED_METHODS.get(cn.name).contains(mn.name))
			// JA_HEALTH_CHECK.getProtectedDB().add("HSQL");
			break;
		case CLASS_COM_MONGODB_ASYNC_CLIENT_OPERATION_EXECUTOR_IMPL:
		case CLASS_COM_MONGODB_ASYNC_CLIENT_ASYNC_OPERATION_EXECUTOR_IMPL:
		case CLASS_COM_MONGODB_ASYNC_CLIENT_MONGO_CLIENT_IMPL$2:
		case CLASS_COM_MONGODB_INTERNAL_CONNECTION_DEFAULT_SERVER_CONNECTION:
		case CLASS_COM_MONGODB_CONNECTION_DEFAULT_SERVER_CONNECTION:
			if (INSTRUMENTED_METHODS.get(cn.name).contains(mn.name))
				JA_HEALTH_CHECK.getProtectedDB().add("MONGO");
			break;
		case CLASS_COM_MYSQL_JDBC_SERVER_PREPARED_STATEMENT:
		case CLASS_COM_MYSQL_CJ_NATIVE_SESSION:
		case CLASS_COM_MYSQL_CJ_MYSQLA_IO_MYSQLA_PROTOCOL:
		case CLASS_COM_MYSQL_JDBC_MYSQL_IO:
			if (INSTRUMENTED_METHODS.get(cn.name).contains(mn.name))
				JA_HEALTH_CHECK.getProtectedDB().add("MYSQL");
			break;
		case CLASS_COM_MICROSOFT_SQLSERVER_JDBC_SQL_SERVER_STATEMENT:
			if (INSTRUMENTED_METHODS.get(cn.name).contains(mn.name))
				JA_HEALTH_CHECK.getProtectedDB().add("MSSQL");
			break;
		case CLASS_JAVA_LANG_PROCESS_IMPL:
			if (INSTRUMENTED_METHODS.get(cn.name).contains(mn.name))
				JA_HEALTH_CHECK.setRceProtection(true);
			break;
		default:
			break;

		}
		boolean isInstrument = INSTRUMENTED_METHODS.get(cn.name).contains(mn.name);
		if (isInstrument) {
			String codeName = cn.name.substring(cn.name.lastIndexOf('/') + 1) + "."
					+ INSTRUMENTED_METHODS.get(cn.name).indexOf(mn.name);
			JA_HEALTH_CHECK.getInstrumentedMethods().add(codeName);
		}
		return isInstrument;
	}

	private void onTerminationOfHookedMethods(Object source, String eId) {
		try {
			Integer executionId = Integer.parseInt(eId.split(COLON_SEPERATOR)[1]);
			String sourceString = null;
			Method m = null;
			long threadId = Thread.currentThread().getId();
			// System.out.println("In doOnThrowableThrown init :" + sourceString + " : " +
			// executionId + " : " + threadId);
			if (source instanceof Method) {
				m = (Method) source;
				sourceString = m.toGenericString();
				// System.out.println("In doOnThrowableThrown :" + sourceString + " : " +
				// executionId + " : " + threadId);
				if (sourceString != null && (TOMCAT_COYOTE_ADAPTER_SERVICE.equals(sourceString)
						|| JETTY_REQUEST_ON_FILLABLE.equals(sourceString))) {
					ServletEventPool.getInstance().decrementServletInfoReference(threadId, executionId, false);
					 System.out.println("Request map entry removed for threadID " + threadId);
					 System.out.println("Current request map : " +
					 ServletEventPool.getInstance().getRequestMap());
					 System.out.println(threadId + ":: remove from coyote");
				}
			}
		} catch (Exception e) {
//			e.printStackTrace();
		}
	}

	@SuppressWarnings({ "rawtypes" })
	@Override
	protected void doOnStart(Object source, Object[] arg, String eId) {
		long start = System.currentTimeMillis();
		String sourceString = null;
		Integer executionId = Integer.parseInt(eId.split(COLON_SEPERATOR)[1]);
		long threadId = Thread.currentThread().getId();
		if (source instanceof Method) {
			sourceString = ((Method) source).toGenericString();

		} else if (source instanceof Constructor) {
			sourceString = ((Constructor) source).toGenericString();
		} else {
			return;
		}

		 System.out.println("source string : " + sourceString);
//		 logger.log(Level.FINE,"Executionid: " + eId);
//		 logger.log(Level.FINE,"Thread Id: " + threadId);
		 logger.log(Level.FINE, "SourceString: " +sourceString);

		if (sourceString == null)
			return;

		if (JETTY_REQUEST_ON_FILLABLE.equals(sourceString)) {
			ServletEventPool.getInstance().incrementServletInfoReference(threadId, executionId, false);
			ServletInfo servletInfo;
			if (!ServletEventPool.getInstance().getRequestMap().containsKey(threadId)) {
				servletInfo = new ServletInfo();
				ConcurrentLinkedDeque<ExecutionMap> executionMaps = new ConcurrentLinkedDeque<ExecutionMap>();
				executionMaps.add(new ExecutionMap(executionId, servletInfo));
				ServletEventPool.getInstance().getRequestMap().put(threadId, executionMaps);

			} else {
				servletInfo = new ServletInfo();
				servletInfo.addGenerationTime((int) (System.currentTimeMillis()-start));
				ServletEventPool.getInstance().getRequestMap().get(threadId)
						.add(new ExecutionMap(executionId, servletInfo));
			}
		} else if (JETTY_PARSE_NEXT.equals(sourceString)) {

			ServletInfo servletInfo = ExecutionMap.find(executionId,
					ServletEventPool.getInstance().getRequestMap().get(threadId));
			if (servletInfo == null) {
				return;
			}
			// if (servletInfo == null) {
			// servletInfo = new ServletInfo();
			// ServletEventPool.getInstance().getRequestMap().get(threadId)
			// .add(new ExecutionMap(executionId, servletInfo));
			// }
			try {
				String requestContent = null;
				Field limit = Buffer.class.getDeclaredField(BYTE_BUFFER_FIELD_LIMIT);
				limit.setAccessible(true);
				Field positionField = Buffer.class.getDeclaredField(BYTE_BUFFER_FIELD_POSITION);
				positionField.setAccessible(true);
				int positionHb = (Integer) positionField.get(arg[0]);
				int limitHb = (Integer) limit.get(arg[0]);
				if (limitHb > 0 && positionHb == 0) {

					Field hb = ByteBuffer.class.getDeclaredField(BYTE_BUFFER_FIELD_HB);
					hb.setAccessible(true);
					byte[] hbContent = (byte[]) hb.get(arg[0]);

					requestContent = new String(hbContent, 0, limitHb, StandardCharsets.UTF_8);
					if (servletInfo.getRawRequest().length() > 8192 || servletInfo.isDataTruncated()) {
						servletInfo.setDataTruncated(true);
					} else {
						servletInfo.setRawRequest(servletInfo.getRawRequest() + requestContent);
					}
					// logger.log(Level.FINE,"Request Param : " + servletInfo);
				}
				servletInfo.addGenerationTime((int) (System.currentTimeMillis()-start));
			} catch (Exception e) {
				logger.log(Level.WARNING, "Exception occured in JETTY_PARSE_NEXT: {0}", e);
			}
		} else if (TOMCAT_SETBYTEBUFFER.equals(sourceString)) {
			ServletInfo servletInfo;
			servletInfo = ExecutionMap.find(executionId, ServletEventPool.getInstance().getRequestMap().get(threadId));
			if (servletInfo == null) {
				return;
			}
			try {
				String requestContent = null;
				Field limit = Buffer.class.getDeclaredField(BYTE_BUFFER_FIELD_LIMIT);
				limit.setAccessible(true);
				Field positionField = Buffer.class.getDeclaredField(BYTE_BUFFER_FIELD_POSITION);
				positionField.setAccessible(true);
				int positionHb = (Integer) positionField.get(arg[0]);

				int limitHb = (Integer) limit.get(arg[0]);
				if (limitHb > 0) {

					Field hb = ByteBuffer.class.getDeclaredField(BYTE_BUFFER_FIELD_HB);
					hb.setAccessible(true);
					byte[] hbContent = (byte[]) hb.get(arg[0]);

					requestContent = new String(hbContent, positionHb, limitHb - positionHb, StandardCharsets.UTF_8);
					if (servletInfo.getRawRequest().length() > 8192 || servletInfo.isDataTruncated()) {
						servletInfo.setDataTruncated(true);
					} else {
						servletInfo.setRawRequest(servletInfo.getRawRequest() + requestContent);
					}
					// logger.log(Level.FINE,"Request Param : " + servletInfo);
				}
				servletInfo.addGenerationTime((int) (System.currentTimeMillis()-start));
			} catch (Exception e) {
				logger.log(Level.WARNING, "Exception occured in TOMCAT_SETBYTEBUFFER: {0}", e);
			}
		} else if (TOMCAT_COYOTE_ADAPTER_SERVICE.equals(sourceString)) {

			ServletEventPool.getInstance().incrementServletInfoReference(threadId, executionId, false);
			if (tomcatVersion == null || tomcatVersion.isEmpty()) {
				setTomcatVersion();
			}

			ServletInfo servletInfo = new ServletInfo();
			if (!ServletEventPool.getInstance().getRequestMap().containsKey(threadId)) {
				ConcurrentLinkedDeque<ExecutionMap> executionMaps = new ConcurrentLinkedDeque<ExecutionMap>();
				executionMaps.add(new ExecutionMap(executionId, servletInfo));
				ServletEventPool.getInstance().getRequestMap().put(threadId, executionMaps);
			} else {
				servletInfo = new ServletInfo();
				ServletEventPool.getInstance().getRequestMap().get(threadId)
						.add(new ExecutionMap(executionId, servletInfo));
			}
			// servletInfo = ExecutionMap.find(executionId,
			// ServletEventPool.getInstance().getRequestMap().get(threadId));
			// if (servletInfo == null) {
			// servletInfo = new ServletInfo();
			// ServletEventPool.getInstance().getRequestMap().get(threadId)
			// .add(new ExecutionMap(executionId, servletInfo));
			// }

			try {
				String requestContent = null;

				Field inputBufferField = arg[0].getClass().getDeclaredField(TOMCAT_REQUEST_FIELD_INPUTBUFFER);
				inputBufferField.setAccessible(true);
				Object inputBuffer = inputBufferField.get(arg[0]);
				Object byteBuffer = null;
				int positionHb = -1;
				boolean byteBufferFound = false;
				if (tomcatMajorVersion == TOMCAT_8 || tomcatMajorVersion == TOMCAT_9) {
					try {
						Field byteBufferField = inputBuffer.getClass()
								.getDeclaredField(TOMCAT_REQUEST_FIELD_BYTEBUFFER);
						byteBufferField.setAccessible(true);
						byteBuffer = byteBufferField.get(inputBuffer);

						Field position = Buffer.class.getDeclaredField(BYTE_BUFFER_FIELD_POSITION);
						position.setAccessible(true);
						positionHb = (Integer) position.get(byteBuffer);
						byteBufferFound = true;
					} catch (Exception e) {
						logger.log(Level.WARNING, "Exception occured in TOMCAT_COYOTE_ADAPTER_SERVICE: {0}", e);
					}
				} else if (tomcatMajorVersion == TOMCAT_7) {
					try {
						if (abstractInputBufferClass == null) {
							abstractInputBufferClass = Class.forName(COYOTE_ABSTRACT_INPUT_BUFFER_CLASS_NAME, true,
									Thread.currentThread().getContextClassLoader());
						}
						Field byteBufferField = abstractInputBufferClass.getDeclaredField(BYTE_BUFFER_FIELD_BUF);
						byteBufferField.setAccessible(true);
						byteBuffer = byteBufferField.get(inputBuffer);

						Field position = abstractInputBufferClass.getDeclaredField(BYTE_BUFFER_FIELD_LASTVALID);
						position.setAccessible(true);
						positionHb = (Integer) position.get(inputBuffer);
						if (positionHb == 8192) {
							servletInfo.setDataTruncated(true);
						}
						byteBufferFound = true;
					} catch (Exception e) {
						logger.log(Level.WARNING, "Exception occured in TOMCAT_COYOTE_ADAPTER_SERVICE: {0}", e);

					}
				}

				if (byteBufferFound && positionHb > 0) {

					byte[] hbContent = null;

					if (tomcatMajorVersion == TOMCAT_8 || tomcatMajorVersion == TOMCAT_9) {
						Field hb = ByteBuffer.class.getDeclaredField(BYTE_BUFFER_FIELD_HB);
						hb.setAccessible(true);
						hbContent = (byte[]) hb.get(byteBuffer);
					} else if (tomcatMajorVersion == TOMCAT_7) {
						hbContent = (byte[]) byteBuffer;
					}

					com.k2cybersecurity.intcodeagent.logging.ByteBuffer buff = preProcessTomcatByteBuffer(hbContent,
							positionHb);
					requestContent = new String(buff.getByteArray(), 0, buff.getLimit(), StandardCharsets.UTF_8);
					servletInfo.setRawRequest(requestContent);
					// logger.log(Level.FINE,"Request Param : " + threadId + ":" + executionId + " :
					// " +
					// servletInfo);
				}
				servletInfo.addGenerationTime((int) (System.currentTimeMillis()-start));
			} catch (Exception e) {
				logger.log(Level.WARNING, "Exception occured in TOMCAT_COYOTE_ADAPTER_SERVICE buffer processing : {0}",
						e);
			}
			// in case of executeInternal()
		} else {

			if (MYSQL_SOURCE_METHOD_LIST.contains(sourceString) && arg[0] != null) {
				processMysqlStatement(arg, threadId, sourceString);
			}
			try {
				if (ServletEventPool.getInstance().getRequestMap().containsKey(threadId) && ExecutionMap
						.find(executionId, ServletEventPool.getInstance().getRequestMap().get(threadId)) != null) {
					ServletEventPool.getInstance().incrementServletInfoReference(threadId, executionId, true);
					EventThreadPool.getInstance().processReceivedEvent(source, arg, executionId,
							Thread.currentThread().getStackTrace(), threadId, sourceString, System.currentTimeMillis()-start);
				}
			} catch (Exception e) {
			}

		}

	}

	@Override
	protected void doOnThrowableThrown(Object source, Throwable throwable, String executionId) {
		onTerminationOfHookedMethods(source, executionId);
	}

	@Override
	protected void doOnThrowableUncatched(Object source, Throwable throwable, String executionId) {
		onTerminationOfHookedMethods(source, executionId);
	}

	@Override
	protected void doOnFinish(Object source, Object result, String executionId) {
		onTerminationOfHookedMethods(source, executionId);
	}

	private void processMysqlStatement(Object[] args, long threadId, String sourceString) {
		int targetObjLocation = 0;
		if (sourceString.equals(MYSQL_CONNECTOR_5_0_4_PREPARED_SOURCE)) {
			targetObjLocation = args.length - 1;
		}
		int thisPointerLocation = args.length - 1;
		Object obj = args[targetObjLocation];
		Class<?> objClass = obj.getClass();

		if (objClass.getName().equals(MYSQL_PREPARED_STATEMENT_5)
				|| objClass.getName().equals(MYSQL_PREPARED_STATEMENT_5_0_4)
				|| objClass.getName().equals(MYSQL_PREPARED_STATEMENT_42)
				|| objClass.getName().equals(MYSQL_PREPARED_STATEMENT_4)) {
			try {
				if (mysqlPreparedStatement5Class == null) {
					mysqlPreparedStatement5Class = Class.forName(MYSQL_PREPARED_STATEMENT_5, true,
							Thread.currentThread().getContextClassLoader());
				}
				objClass = mysqlPreparedStatement5Class;
				Field originalSqlField = objClass.getDeclaredField(MYSQL_FIELD_ORIGINAL_SQL);
				originalSqlField.setAccessible(true);
				String originalSql = (String) originalSqlField.get(obj);
				args[thisPointerLocation] = originalSql;
			} catch (Exception e) {
				logger.log(Level.WARNING, "Exception occured in processMysqlStatement CONNECTOR_5: {0}", e);
			}
		} else if (objClass.getName().equals(MYSQL_PREPARED_STATEMENT_6)
				&& (sourceString.equals(MYSQL_CONNECTOR_6_SOURCE) || sourceString.equals(MYSQL_CONNECTOR_6_0_2_SOURCE)
						|| sourceString.equals(MYSQL_CONNECTOR_6_0_3_SOURCE))) {
			try {
				Field originalSqlField = objClass.getDeclaredField(MYSQL_FIELD_ORIGINAL_SQL);
				originalSqlField.setAccessible(true);
				String originalSql = (String) originalSqlField.get(obj);

				args[thisPointerLocation] = originalSql;
			} catch (Exception e) {
				logger.log(Level.WARNING, "Exception occured in processMysqlStatement CONNECTOR_6 : {0}", e);
			}
		} else if (objClass.getName().equals(MYSQL_PREPARED_STATEMENT_8)
				&& sourceString.equals(MYSQL_CONNECTOR_8_SOURCE)) {
			try {
				Field queryField = objClass.getSuperclass().getDeclaredField(MYSQL_FIELD_QUERY);
				queryField.setAccessible(true);
				Object query = queryField.get(obj);
				if (query != null && query.getClass().getName().equals(MYSQL_PREPARED_QUERY_8)) {

					if (mysqlPreparedStatement8Class == null) {
						mysqlPreparedStatement8Class = Class.forName(MYSQL_PREPARED_STATEMENT_SOURCE_8, true,
								Thread.currentThread().getContextClassLoader());
					}

					objClass = mysqlPreparedStatement8Class;
					Field originalSqlField = objClass.getDeclaredField(MYSQL_FIELD_ORIGINAL_SQL);
					originalSqlField.setAccessible(true);
					String originalSql = (String) originalSqlField.get(query);
					args[thisPointerLocation] = originalSql;
				}
			} catch (Exception e) {
				logger.log(Level.WARNING, "Exception occured in processMysqlStatement CONNECTOR_8 : {0}", e);
			}

		}

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
				fos.write(NEW_LINE_SEQUENCE.getBytes());
			} finally {
				fos.close();
			}
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
	}

	private static void setTomcatVersion() {
		try {
			Class<?> serverInfo = Class.forName(TOMCAT_SERVER_INFO_CLASS_NAME, true,
					Thread.currentThread().getContextClassLoader());
			Field serverNumberField = serverInfo.getDeclaredField(TOMCAT_FIELD_SERVERNUMBER);
			serverNumberField.setAccessible(true);
			tomcatVersion = (String) serverNumberField.get(null);

			tomcatMajorVersion = Integer.parseInt(tomcatVersion.split(VERSION_SPLIT_EXPR)[0]);
			logger.log(Level.INFO, TOMCAT_VERSION_DETECTED_MSG + tomcatMajorVersion + COLON_SEPERATOR + tomcatVersion);

		} catch (Exception e) {
			logger.log(Level.WARNING, "Unable to find Tomcat Version: {0}", e);
		}
	}

	protected static void closeSocket() {
		if (EventThreadPool.getInstance().getSocket() != null) {
			try {
				EventThreadPool.getInstance().getSocket().close();
				EventThreadPool.getInstance().setSocket(null);
			} catch (IOException e) {
				logger.log(Level.WARNING, "Error in closeSocket: {0}", e);
			}
		}
	}

	public static void setLogger() {
		LoggingInterceptor.logger = Logger.getLogger(LoggingInterceptor.class.getName());
	}

	@Override
	public boolean addShutDownHook(Runtime runtime) {
		runtime.addShutdownHook(new Thread() {
			@Override
			public void run() {
				ShutDownEvent shutDownEvent = new ShutDownEvent();
				shutDownEvent.setApplicationUUID(Agent.APPLICATION_UUID);
				shutDownEvent.setStatus("Terminating");
				EventThreadPool.getInstance().getEventQueue().add(shutDownEvent);
				logger.log(Level.INFO, "Shutting down with status: " + shutDownEvent);
				try {
					TimeUnit.SECONDS.sleep(1);
				} catch (InterruptedException e) {
				}
				disconnectSocket();
				ServletEventPool.getInstance().shutDownThreadPoolExecutor();
				IPScheduledThread.getInstance().shutDownThreadPoolExecutor();
				EventThreadPool.getInstance().shutDownThreadPoolExecutor();
			}
		});
		return false;
	}

}
