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

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.SocketAddress;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URISyntaxException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.nio.file.Paths;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.brutusin.instrumentation.Agent;
import org.brutusin.instrumentation.Interceptor;
import org.json.simple.JSONArray;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.ApplicationInfoBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.FileIntegrityBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.JAHealthCheck;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.JAHealthCheck;
import com.k2cybersecurity.intcodeagent.models.javaagent.ShutDownEvent;
import com.k2cybersecurity.intcodeagent.models.javaagent.VulnerabilityCaseType;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.k2cybersecurity.intcodeagent.websocket.WSClient;

public class LoggingInterceptor extends Interceptor {

	private static final String STRING_DOT = ".";
	private static final char CH_SLASH = '/';
	private static final String FIELD_POS = "pos";
	private static final String WEBLOGIC_UTILS_IO_NULL_INPUT_STREAM = "weblogic.utils.io.NullInputStream";
	private static final String FIELD_NAME_CONTENT_LEN = "contentLen";
	private static final String FIELD_NAME_IN3 = "in";
	private static final String FIELD_CONN_HANDLER = "connHandler";
	private static final String FIELD_NAME_INPUT_STREAM = "inputStream";
	private static final String BYTE_LIMIT = "byteLimit";
	private static final String BYTE_CACHE = "byteCache";
	private static final String CLASS_COM_IBM_WS_GENERICBNF_IMPL_BNF_HEADERS_IMPL = "com.ibm.ws.genericbnf.impl.BNFHeadersImpl";
	private static final String CLASS_COM_IBM_WS_GENERICBNF_INTERNAL_BNF_HEADERS_IMPL = "com.ibm.ws.genericbnf.internal.BNFHeadersImpl";
	private static final String SCOPE = ".scope";
	private static final String DOCKER_1_13 = "/docker-";
	public static Integer VMPID;
	protected static final String applicationUUID;
	public static ApplicationInfoBean APPLICATION_INFO_BEAN;
	protected static JAHealthCheck JA_HEALTH_CHECK;

	protected static Class<?> mysqlPreparedStatement8Class, mysqlPreparedStatement5Class, abstractInputBufferClass,
			postInputStreamClass, jettyAbstractConnection;
	protected static String tomcatVersion;
	protected static int tomcatMajorVersion;
	static final int MAX_DEPTH_LOOKUP = 4; // Max number of superclasses to lookup for a field
	// protected static Map<Long, ServletInfo> requestMap;
	public static String hostip = "";
//	private static Logger logger;

	private boolean isOldWildfly = false;
	
	private static final FileLoggerThreadPool logger;

	private static Pattern applicationInformationDetectRegex = Pattern.compile("\\S*(\\/classes)\\S*");

	static {
		try {
			RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
			String runningVM = runtimeMXBean.getName();
			VMPID = Integer.parseInt(runningVM.substring(0, runningVM.indexOf(VMPID_SPLIT_CHAR)));
		} catch (Throwable th) {
			System.err.println("Error while initialising the K2 Agent :" + th.getCause() + " : " + th.getMessage());
		}
		applicationUUID = Agent.APPLICATION_UUID;
		logger = FileLoggerThreadPool.getInstance();
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
			ApplicationInfoBean applicationInfoBean = new ApplicationInfoBean(VMPID, applicationUUID,
					Agent.isDynamicAttach ? "DYNAMIC" : "STATIC");
			applicationInfoBean.setStartTime(runtimeMXBean.getStartTime());
			String containerId = getContainerID();
			String cmdLine = StringEscapeUtils.escapeJava(getCmdLineArgsByProc(VMPID));
			applicationInfoBean.setProcStartTime(getStartTimeByProc(VMPID));
			applicationInfoBean.setCmdline(cmdLine);
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
			logger.log(LogLevel.WARNING, "Exception occured in createApplicationInfoBean: ", e,
					LoggingInterceptor.class.getName());
		}
		return null;
	}

	public static void updateServerInfo() {
		Set<DeployedApplication> deployedApplications = getAllDeployedApplications();
		JSONArray jsonArray = new JSONArray();
		jsonArray.addAll(deployedApplications);

		if (!APPLICATION_INFO_BEAN.getServerInfo().getDeployedApplications().containsAll(jsonArray)) {
			APPLICATION_INFO_BEAN.getServerInfo().setDeployedApplications(jsonArray);
			EventSendPool.getInstance().sendEvent(APPLICATION_INFO_BEAN.toString());
		}
	}

	private static Set<DeployedApplication> getAllDeployedApplications() {
		Set<DeployedApplication> deployedApplications = new HashSet<>();
//		logger.debug(OBTAINED_INFORMATION);
//		logger.debug(CLASS_PATHS, classPaths);
		Matcher pathMatcher;
		String[] pathList;
		String filePath;
		File pathFile;

		for (String path : Agent.jarPathSet) {
			filePath = path;
			filePath = StringUtils.removeAll(filePath, "!");
			pathMatcher = applicationInformationDetectRegex.matcher(filePath);
			if (pathMatcher.find()) {
				pathFile = new File(filePath);
				while (StringUtils.isNotBlank(pathFile.getName())) {
					if (StringUtils.equals(pathFile.getName(), "classes")) {
						break;
					}
					pathFile = pathFile.getParentFile();
				}
				if (StringUtils.equals(pathFile.getName(), "classes")) {
					pathFile = pathFile.getParentFile();
					if (StringUtils.endsWith(pathFile.getName(), "INF")) {
						pathFile = pathFile.getParentFile();
						if (StringUtils.endsWith(pathFile.getName(), "webapp")) {
							deployedApplications.add(new DeployedApplication(pathFile.getParentFile().getAbsolutePath(),
									pathFile.getParentFile().getName()));
						}
						deployedApplications
								.add(new DeployedApplication(pathFile.getAbsolutePath(), pathFile.getName()));
					} else {
						deployedApplications
								.add(new DeployedApplication(pathFile.getAbsolutePath(), pathFile.getName()));
					}
				}
			}
		}
		return deployedApplications;
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
//		System.out.println("Classloader of LoggingInterceptor class inside is : " + this.getClass().getClassLoader());
		try (BufferedReader reader = new BufferedReader(new FileReader(HOST_IP_PROPERTIES_FILE))) {
			hostip = reader.readLine();
			if (hostip != null)
				hostip = hostip.trim();
		}
//		ConfigK2Logs.getInstance().initializeLogs();
		APPLICATION_INFO_BEAN = createApplicationInfoBean();
		JA_HEALTH_CHECK = new JAHealthCheck(applicationUUID);
		try {
			WSClient.getInstance();
		} catch (Exception e) {
			logger.log(LogLevel.ERROR, "Error occured while trying to connect to wsocket: ", e,
					LoggingInterceptor.class.getName());
		}
		IPScheduledThread.getInstance();
		eventWritePool();
	}

	private static void eventWritePool() {

		try {
			EventSendPool.getInstance();
		} catch (Exception e) {
			logger.log(LogLevel.WARNING, "Exception occured in EventSendPool: ", e, LoggingInterceptor.class.getName());
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
		if ("openConnectoin".equalsIgnoreCase(mn.name))
			return true;
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
		case CLASS_WEBLOGIC_SERVLET_INTERNAL_WEB_APP_SERVLET_CONTEXT:
			if (INSTRUMENTED_METHODS.get(cn.name).contains(mn.name))
				JA_HEALTH_CHECK.setProtectedServer("WEBLOGIC");
			break;
		case COM_IBM_WS_HTTP_CHANNEL_INTERNAL_INBOUND_HTTPINBOUNDLINK:
			if (INSTRUMENTED_METHODS.get(cn.name).contains(mn.name))
				JA_HEALTH_CHECK.setProtectedServer("WEBSPHERE_LIBERTY");
			break;
		case COM_IBM_WS_HTTP_CHANNEL_INBOUND_IMPL_HTTPINBOUNDLINK:
			if (INSTRUMENTED_METHODS.get(cn.name).contains(mn.name))
				JA_HEALTH_CHECK.setProtectedServer("WEBSPHERE_TRADITIONAL");
			break;
		case IO_UNDERTOW_SERVLET_HANDLERS_SERVLET_HANDLER:
			if (INSTRUMENTED_METHODS.get(cn.name).contains(mn.name))
				JA_HEALTH_CHECK.setProtectedServer("JBOSS");
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
		case CLASS_HTTP_REQUEST_EXECUTOR:
		case CLASS_JAVA_HTTP_HANDLER:
		case CLASS_JAVA_HTTPS_HANDLER:
		case CLASS_JAVA_SSL_HTTPS_HANDLER:
		case CLASS_JDK_INCUBATOR_HTTP_MULTIEXCHANGE:
		case CLASS_APACHE_COMMONS_HTTP_METHOD_DIRECTOR:
		case CLASS_OKHTTP_HTTP_ENGINE:
		case CLASS_WEBLOGIC_HTTP_HANDLER:
			if (INSTRUMENTED_METHODS.get(cn.name).contains(mn.name))
				JA_HEALTH_CHECK.setSsrfProtection(true);
			break;
		case CLASS_JAVA_IO_FILE_OUTPUT_STREAM:
		case CLASS_JAVA_IO_FILE_INPUT_STREAM:
		case CLASS_SUN_NIO_FS_UNIX_NATIVE_DISPATCHER:
			if (INSTRUMENTED_METHODS.get(cn.name).contains(mn.name))
				JA_HEALTH_CHECK.setFileAccessProtection(true);
			break;
		default:
			break;

		}
		boolean isInstrument = INSTRUMENTED_METHODS.get(cn.name).contains(mn.name);
		if (isInstrument) {
			String codeName = cn.name.substring(cn.name.lastIndexOf(CH_SLASH) + 1) + STRING_DOT
					+ INSTRUMENTED_METHODS.get(cn.name).indexOf(mn.name);
			JA_HEALTH_CHECK.getInstrumentedMethods().add(codeName);
//			System.out.println("Class name: " + cn.name + " , method: " + mn.name);
		}
		return isInstrument;
	}

	private void onTerminationOfHookedMethods(Object source, String eId) {
		try {
			Long executionId = Long.parseLong(eId.split(COLON_SEPERATOR)[1]);
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
				if (sourceString != null
						&& (TOMCAT_COYOTE_ADAPTER_SERVICE.equals(sourceString)
								|| JETTY_REQUEST_ON_FILLABLE.equals(sourceString))
						|| sourceString.equals(WEBSPHERE_LIBERTY_PROCESSREQUEST)
						|| sourceString.equals(WEBSPHERE_TRADITIONAL_PROCESSREQUEST)
						|| sourceString.equals(
								PUBLIC_VOID_IO_UNDERTOW_SERVLET_HANDLERS_SERVLET_HANDLER_HANDLE_REQUEST_IO_UNDERTOW_SERVER_HTTP_SERVER_EXCHANGE_THROWS_JAVA_IO_IO_EXCEPTION_JAVAX_SERVLET_SERVLET_EXCEPTION)
						|| sourceString.equals(WEBLOGIC_SERVLET_EXECUTE)) {
					long start = System.currentTimeMillis();
					HttpRequestBean httpRequest = ExecutionMap.find(executionId,
							ServletEventPool.getInstance().getRequestMap().get(threadId));
					Map<String, FileIntegrityBean> fileMap = httpRequest.getFileExist();
					for (Entry<String, FileIntegrityBean> entry : fileMap.entrySet()) {
						if (!entry.getValue().getExists().equals(new File(entry.getKey()).exists())) {
							// Generate file integrity event add entry.getValue()
							EventThreadPool.getInstance().processReceivedEvent(source, new String[] { entry.getKey() },
									executionId, threadId, entry.getValue(), System.currentTimeMillis() - start,
									new HttpRequestBean(httpRequest), VulnerabilityCaseType.FILE_INTEGRITY);
						}
					}
					ServletEventPool.getInstance().decrementServletInfoReference(threadId, executionId, false);
//					System.out.println("Current request map : " + ServletEventPool.getInstance().getRequestMap());
//					System.out.println("Current MappedThreadIDToRemove" + ThreadMapping.getInstance().getMappedThreadIDToRemove());
//					System.out.println("Current TempThreadRequestMap" + ThreadMapping.getInstance().getTempThreadRequestMap());
//					System.out.println("Current MappedThreadRequestMap" + ThreadMapping.getInstance().getMappedThreadRequestMap());
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
		Long executionId = Long.parseLong(eId.split(COLON_SEPERATOR)[1]);
		long threadId = Thread.currentThread().getId();
		if (source instanceof Method) {
			sourceString = ((Method) source).toGenericString();

		} else if (source instanceof Constructor) {
			sourceString = ((Constructor) source).toGenericString();
		} else {
			return;
		}

//		 // logger.log(LogLevel.FINE,"Executionid: " + eId);
//		 // logger.log(LogLevel.FINE,"Thread Id: " + threadId);
		// logger.log(LogLevel.FINE, "SourceString: " +sourceString);

//		System.out.println("start Executionid: " + eId);
//		System.out.println("start Thread Id: " + threadId);
//		System.out.println("start SourceString: " + sourceString);
//		logger.log(LogLevel.INFO, "OnStart source: " + sourceString + " :: args: " + Arrays.asList(arg[0]) + " :: eid: " + eId,LoggingInterceptor.class.getName());

		if (sourceString == null)
			return;
		if (sourceString.equals(PUBLIC_VOID_ORG_XNIO_XNIO_WORKER_EXECUTE_JAVA_LANG_RUNNABLE)) {
			Object thisPointer = arg[arg.length - 1];
			ClassLoader currentClassLoader = thisPointer.getClass().getClassLoader();
			try {
				Field taskQueue = Class.forName(ORG_XNIO_XNIO_WORKER, true, currentClassLoader)
						.getDeclaredField(TASK_QUEUE);
				taskQueue.setAccessible(true);
				Object taskQueueObj = taskQueue.get(thisPointer);

				Field notEmpty = taskQueueObj.getClass().getDeclaredField(NOT_EMPTY);
				notEmpty.setAccessible(true);
				Condition notEmptyObj = (Condition) notEmpty.get(taskQueueObj);

				// here it is assumed that notEmpty will not be of type SimpleLock which belongs
				// to jboss, as there are
				// three implementations of Condition interface which stores notEmpty object

				Field firstWaiter = notEmptyObj.getClass().getDeclaredField(FIRST_WAITER);
				firstWaiter.setAccessible(true);
				Object firstWaiterObj = firstWaiter.get(notEmptyObj);
				if (firstWaiterObj != null) {
					Field thread = firstWaiterObj.getClass().getDeclaredField(FIELD_THREAD);
					thread.setAccessible(true);
					Thread threadObj = (Thread) thread.get(firstWaiterObj);
					long newThreadId = threadObj.getId();
//			System.out.println("Now created thread id : "+ threadObj.getId());
					Pair<Long, Long> oldPairedKey = new ImmutablePair<Long, Long>(threadId, executionId - 1);
					ThreadMapping.getInstance().getMappedThreadIDToRemove().put(oldPairedKey, newThreadId);
					updateThreadMaps(threadId, executionId, newThreadId, 1);
//			System.out.println("ExecuteUpdated : "+ ThreadMapping.getInstance().getMappedThreadRequestMap());
				}
			} catch (Throwable e) {
//				e.printStackTrace();
			}

		} else if (sourceString.equals(
				PUBLIC_VOID_IO_UNDERTOW_SERVLET_HANDLERS_SERVLET_HANDLER_HANDLE_REQUEST_IO_UNDERTOW_SERVER_HTTP_SERVER_EXCHANGE_THROWS_JAVA_IO_IO_EXCEPTION_JAVAX_SERVLET_SERVLET_EXCEPTION)) {
//			Map<Thread, StackTraceElement[]> map = Thread.currentThread().getAllStackTraces();
//			for(Entry<Thread, StackTraceElement[]> entry : map.entrySet()) {
//				System.out.println("Thread : "+ entry.getKey().getName());
//				for(StackTraceElement st : entry.getValue()) {
//					System.out.println("CN : "+st.getClassName()+ "  ::: MN : "+st.getMethodName()+" :: LN :"+ st.getLineNumber());
//				}
//			}
//			System.out.println("In runnable.run : " + ThreadMapping.getInstance().getMappedThreadRequestMap());
			ServletEventPool.getInstance().incrementServletInfoReference(threadId, executionId, false);
			if (ThreadMapping.getInstance().getMappedThreadRequestMap().containsKey(threadId)
					&& !ThreadMapping.getInstance().getMappedThreadRequestMap().get(threadId).isEmpty()) {
				// TODO change logic here... use nearest eid instead of latest

				ConcurrentLinkedDeque<ThreadRequestData> threadRequestDatas = ThreadMapping.getInstance()
						.getMappedThreadRequestMap().get(threadId);
				Iterator<ThreadRequestData> iterator = threadRequestDatas.descendingIterator();
				HttpRequestBean servletInfo = null;
				while (iterator.hasNext()) {
					ThreadRequestData threadRequestData = iterator.next();
					if (threadRequestData.getExecutionId() < executionId) {
						servletInfo = threadRequestData.getServletInfo();
//						System.err.println("SI found : "+ servletInfo);
						break;
					}

				}
				if (servletInfo == null) {
//					System.err.println("No SI Mapped");
					return;
				}
				String remoteAddress = getRemoteAddressForWildfly(arg[0]);
				if(remoteAddress!=null)
					servletInfo.setClientIP(remoteAddress);
				ThreadMapping.getInstance().getMappedThreadRequestMap().get(threadId).removeFirst();
				if (ThreadMapping.getInstance().getMappedThreadRequestMap().get(threadId).size() == 0) {
					ThreadMapping.getInstance().getMappedThreadRequestMap().remove(threadId);
				}
				if (!ServletEventPool.getInstance().getRequestMap().containsKey(threadId)) {
					ConcurrentLinkedDeque<ExecutionMap> executionMaps = new ConcurrentLinkedDeque<ExecutionMap>();
					executionMaps.add(new ExecutionMap(executionId, servletInfo));
					ServletEventPool.getInstance().getRequestMap().put(threadId, executionMaps);
				} else {
					ServletEventPool.getInstance().getRequestMap().get(threadId)
							.add(new ExecutionMap(executionId, servletInfo));
				}
			}
		} else if (sourceString
				.equals(PRIVATE_INT_ORG_JBOSS_THREADS_ENHANCED_QUEUE_EXECUTOR_TRY_EXECUTE_JAVA_LANG_RUNNABLE)) {
			Object thisPointer = arg[arg.length - 1];
			ClassLoader currentClassLoader = thisPointer.getClass().getClassLoader();
			try {
				Field tailField = Class.forName(ORG_JBOSS_THREADS_ENHANCED_QUEUE_EXECUTOR, true, currentClassLoader)
						.getDeclaredField(TAIL);
				tailField.setAccessible(true);
				Object tailObject = tailField.get(thisPointer);
				Object tailNext = this.getNextQnode(tailObject, currentClassLoader);
				Class taskNodeClass = Class.forName(ORG_JBOSS_THREADS_ENHANCED_QUEUE_EXECUTOR$_TASK_NODE, true,
						currentClassLoader);
				if (taskNodeClass.isInstance(tailNext)) {
					do {
						tailObject = tailNext;
						tailNext = this.getNextQnode(tailObject, currentClassLoader);
					} while (taskNodeClass.isInstance(tailNext));

				}
				Class poolThreadNodeClass = Class.forName(ORG_JBOSS_THREADS_ENHANCED_QUEUE_EXECUTOR$_POOL_THREAD_NODE,
						true, currentClassLoader);

				Field threadField = Class
						.forName(ORG_JBOSS_THREADS_ENHANCED_QUEUE_EXECUTOR$_POOL_THREAD_NODE, true, currentClassLoader)
						.getDeclaredField(FIELD_THREAD);
				threadField.setAccessible(true);

				if (tailNext != null && poolThreadNodeClass.isInstance(tailNext)) {
					Thread threadObj = (Thread) threadField.get(tailNext);
					Long newThreadId = threadObj.getId();
//					System.out.println("Thread ID Found : " + newThreadId);
					Pair<Long, Long> oldPairedKey = new ImmutablePair<Long, Long>(threadId, executionId - 2);
					ThreadMapping.getInstance().getMappedThreadIDToRemove().put(oldPairedKey, newThreadId);
					updateThreadMaps(threadId, executionId, newThreadId, 2);
				}
			} catch (Exception e) {
				logger.log(LogLevel.WARNING, "Error while processing JBoss inital hook  : ", e,
						this.getClass().getName());
			}
		} else if (sourceString.equals(JBOSS_WILDFLY_HTTP_REQUEST_PARSER_HANDLE)
				|| sourceString.equals(JBOSS_WILDFLY_HTTP_REQUEST_PARSER_HANDLE_2)) {
			Object arg0 = arg[0];
			ClassLoader currentClassLoader = arg0.getClass().getClassLoader();
			String fetchedDataString = fetchRequestStringForWildfly(arg0, currentClassLoader);
			if (sourceString.equals(JBOSS_WILDFLY_HTTP_REQUEST_PARSER_HANDLE_2)) {
				isOldWildfly = true;
			}
			if (fetchedDataString != null && !fetchedDataString.isEmpty()) {
				HttpRequestBean servletInfo = new HttpRequestBean();
				servletInfo.setRawRequest(fetchedDataString);
				ThreadRequestData threadRequestData = new ThreadRequestData(executionId, servletInfo, threadId);
				Pair<Long, Long> pairedKey = new ImmutablePair<>(threadId, executionId);
				if (!ThreadMapping.getInstance().getTempThreadRequestMap().containsKey(pairedKey)) {
					ThreadMapping.getInstance().getTempThreadRequestMap().put(pairedKey,
							new ConcurrentLinkedDeque<ThreadRequestData>());
				}
				ThreadMapping.getInstance().getTempThreadRequestMap().get(pairedKey).add(threadRequestData);
//				System.out.println("Post handle method hook: "+ ThreadMapping.getInstance().getTempThreadRequestMap());
			}
		} else if (sourceString.equals(WEBSPHERE_LIBERTY_FILLBYTECACHE)
				|| sourceString.equals(WEBSPHERE_TRADITIONAL_FILLBYTECACHE))
			return;
		else if (sourceString.equals(WEBSPHERE_LIBERTY_PROCESSREQUEST)
				|| sourceString.equals(WEBSPHERE_TRADITIONAL_PROCESSREQUEST)) {
//			Object thisPointer = arg[arg.length -1];
//			ClassLoader currentClassLoader = arg[arg.length -1].getClass().getClassLoader();
//			int bytePosition = -1;
//			try {
//				Class<?> BNFHeadersImpl = Class.forName("com.ibm.ws.genericbnf.internal.BNFHeadersImpl", true, currentClassLoader);
//
//				Field bytePositionField = BNFHeadersImpl.getDeclaredField("bytePosition");
//				bytePositionField.setAccessible(true);
//				bytePosition = (int )bytePositionField.get(thisPointer);
//				System.out.println("entry : " + bytePosition);
//			} catch (Exception e) {
//				e.printStackTrace();
//			}
//			if(bytePosition>0) {
//
//			} else {
			String remoteAddress = getRemoteAddressForWebsphere(arg[arg.length-1], sourceString);
			ServletEventPool.getInstance().incrementServletInfoReference(threadId, executionId, false);
			HttpRequestBean servletInfo;
			if (!ServletEventPool.getInstance().getRequestMap().containsKey(threadId)) {
				servletInfo = new HttpRequestBean();
				if(remoteAddress!=null)
					servletInfo.setClientIP(remoteAddress);
				ConcurrentLinkedDeque<ExecutionMap> executionMaps = new ConcurrentLinkedDeque<ExecutionMap>();
				executionMaps.add(new ExecutionMap(executionId, servletInfo));
				ServletEventPool.getInstance().getRequestMap().put(threadId, executionMaps);
			} else {
				servletInfo = new HttpRequestBean();
				if(remoteAddress!=null)
					servletInfo.setClientIP(remoteAddress);
				ServletEventPool.getInstance().getRequestMap().get(threadId)
						.add(new ExecutionMap(executionId, servletInfo));
			}
//			}
		} else if (JETTY_REQUEST_ON_FILLABLE.equals(sourceString)) {
			ServletEventPool.getInstance().incrementServletInfoReference(threadId, executionId, false);
			HttpRequestBean servletInfo;
			if (!ServletEventPool.getInstance().getRequestMap().containsKey(threadId)) {
				servletInfo = new HttpRequestBean();
				ConcurrentLinkedDeque<ExecutionMap> executionMaps = new ConcurrentLinkedDeque<ExecutionMap>();
				executionMaps.add(new ExecutionMap(executionId, servletInfo));
				ServletEventPool.getInstance().getRequestMap().put(threadId, executionMaps);

			} else {
				servletInfo = new HttpRequestBean();
				servletInfo.addGenerationTime((int) (System.currentTimeMillis() - start));
				ServletEventPool.getInstance().getRequestMap().get(threadId)
						.add(new ExecutionMap(executionId, servletInfo));
			}
			Object thisVar = arg[arg.length - 1];
			try {
				if(jettyAbstractConnection == null)
					jettyAbstractConnection = Class.forName("org.eclipse.jetty.io.AbstractConnection", true,
							Thread.currentThread().getContextClassLoader());

				Field _endPoint = jettyAbstractConnection.getDeclaredField("_endPoint");
				_endPoint.setAccessible(true);
				Object _endPointObject = _endPoint.get(thisVar);
				Method getRemoteAddress = _endPointObject.getClass().getMethod("getRemoteAddress", null);
				getRemoteAddress.setAccessible(true);
				InetSocketAddress inetSocketAddress = (InetSocketAddress) getRemoteAddress.invoke(_endPointObject,
						null);
				servletInfo.setClientIP(inetSocketAddress.getHostString());
				System.out.println("Client address jetty: " + inetSocketAddress.getHostString());
			} catch (Exception e) {
				e.printStackTrace();
			}

		} else if (JETTY_PARSE_NEXT.equals(sourceString)) {

			HttpRequestBean servletInfo = ExecutionMap.find(executionId,
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
//					 logger.log(LogLevel.FINE,"Request Param : " + servletInfo);
				}
				servletInfo.addGenerationTime((int) (System.currentTimeMillis() - start));
			} catch (Exception e) {
				logger.log(LogLevel.WARNING, "Exception occured in JETTY_PARSE_NEXT: ", e,
						LoggingInterceptor.class.getName());
				e.printStackTrace();
			}
		} else if (TOMCAT_SETBYTEBUFFER.equals(sourceString)) {
			HttpRequestBean servletInfo;
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
//					  logger.log(LogLevel.FINE,"Request Param : " + servletInfo);
				}
				servletInfo.addGenerationTime((int) (System.currentTimeMillis() - start));
			} catch (Exception e) {
				logger.log(LogLevel.WARNING, "Exception occured in TOMCAT_SETBYTEBUFFER: ", e,
						LoggingInterceptor.class.getName());
			}
		} else if (TOMCAT_COYOTE_ADAPTER_SERVICE.equals(sourceString)) {

			ServletEventPool.getInstance().incrementServletInfoReference(threadId, executionId, false);
			if (tomcatVersion == null || tomcatVersion.isEmpty()) {
				setTomcatVersion();
			}

			HttpRequestBean servletInfo = new HttpRequestBean();
			if (!ServletEventPool.getInstance().getRequestMap().containsKey(threadId)) {
				ConcurrentLinkedDeque<ExecutionMap> executionMaps = new ConcurrentLinkedDeque<ExecutionMap>();
				executionMaps.add(new ExecutionMap(executionId, servletInfo));
				ServletEventPool.getInstance().getRequestMap().put(threadId, executionMaps);
			} else {
				servletInfo = new HttpRequestBean();
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

				Field notesField = arg[0].getClass().getDeclaredField("notes");
				notesField.setAccessible(true);
				Object[] notes = (Object[]) notesField.get(arg[0]);
				Object request = notes[1];
				if (request != null) {
					Method getRemoteAddrMethod = request.getClass().getDeclaredMethod("getRemoteAddr", null);
					getRemoteAddrMethod.setAccessible(true);
					String remoteAddr = (String) getRemoteAddrMethod.invoke(request, null);
					servletInfo.setClientIP(remoteAddr);
				}
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
						logger.log(LogLevel.WARNING, "Exception occured in TOMCAT_COYOTE_ADAPTER_SERVICE: ", e,
								LoggingInterceptor.class.getName());
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
						logger.log(LogLevel.WARNING, "Exception occured in TOMCAT_COYOTE_ADAPTER_SERVICE: ", e,
								LoggingInterceptor.class.getName());

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
//					logger.log(LogLevel.INFO, "Request Param : " + threadId + ":" + executionId + " : " + servletInfo,
//							LoggingInterceptor.class.getName());
				}
				servletInfo.addGenerationTime((int) (System.currentTimeMillis() - start));
			} catch (Exception e) {
				logger.log(LogLevel.WARNING, "Exception occured in TOMCAT_COYOTE_ADAPTER_SERVICE buffer processing : ",
						e, LoggingInterceptor.class.getName());
			}
			// in case of executeInternal()
		} else if (sourceString.equals(WEBLOGIC_SERVLET_EXECUTE)) {
			try {
				HttpRequestBean servletInfo = new HttpRequestBean();

				ServletEventPool.getInstance().incrementServletInfoReference(threadId, executionId, false);
				Object servletObject = arg[0];
//				System.out.println("Searching arg0 in : "+ servletObject.getClass().getName() + "  ::  " + servletObject.getClass().getSuperclass().getName() + " :: " + Arrays.asList(servletObject.getClass().getDeclaredFields()));

                Field connectionField = servletObject.getClass().getDeclaredField(FIELD_CONNECTION);
                connectionField.setAccessible(true);
                Object connection = connectionField.get(servletObject);

                Field socketField = connection.getClass().getDeclaredField("socket");
                socketField.setAccessible(true);
                Object socket = socketField.get(connection);

                Method getRemoteSocketAddressMethod = socket.getClass().getMethod("getRemoteSocketAddress", null);
                InetSocketAddress remoteAddr = (InetSocketAddress) getRemoteSocketAddressMethod.invoke(socket, null);

				servletInfo.setClientIP(remoteAddr.getHostString());

                Field inputStreamField = servletObject.getClass().getDeclaredField(FIELD_NAME_INPUT_STREAM);
				inputStreamField.setAccessible(true);
				Object inputStream = inputStreamField.get(servletObject);

				Field inField = inputStream.getClass().getDeclaredField(FIELD_NAME_IN3);
				inField.setAccessible(true);
				Object in = inField.get(inputStream);
				if (!in.getClass().getName().equals(WEBLOGIC_UTILS_IO_NULL_INPUT_STREAM)) {
//					System.out.println("Searching buf in : "+ in.getClass().getName() + "  ::  " + in.getClass().getSuperclass().getName() + " :: " + Arrays.asList(in.getClass().getDeclaredFields()));
					Field bufField = in.getClass().getDeclaredField(BYTE_BUFFER_FIELD_BUF);
					bufField.setAccessible(true);
					Object buf = bufField.get(in);

					Field contentLenField = in.getClass().getDeclaredField(FIELD_NAME_CONTENT_LEN);
					contentLenField.setAccessible(true);
					Long contentLen = (Long) contentLenField.get(in);

					Field limit = Buffer.class.getDeclaredField(BYTE_BUFFER_FIELD_LIMIT);
					limit.setAccessible(true);
					int limitHb = (Integer) limit.get(buf);
					if (limitHb > 0) {

						Field hb = ByteBuffer.class.getDeclaredField(BYTE_BUFFER_FIELD_HB);
						hb.setAccessible(true);
						byte[] hbContent = (byte[]) hb.get(buf);

						servletInfo.setRawRequest(new String(hbContent, 0, limitHb, StandardCharsets.UTF_8));
						if (contentLen > limitHb) {
							servletInfo.setDataTruncated(true);
						}

						servletInfo.addGenerationTime((int) (System.currentTimeMillis() - start));
						if (!ServletEventPool.getInstance().getRequestMap().containsKey(threadId)) {
							ConcurrentLinkedDeque<ExecutionMap> executionMaps = new ConcurrentLinkedDeque<ExecutionMap>();
							executionMaps.add(new ExecutionMap(executionId, servletInfo));
							ServletEventPool.getInstance().getRequestMap().put(threadId, executionMaps);

						} else {
							servletInfo.addGenerationTime((int) (System.currentTimeMillis() - start));
							ServletEventPool.getInstance().getRequestMap().get(threadId)
									.add(new ExecutionMap(executionId, servletInfo));
						}
//					System.out.println("request map: "+ServletEventPool.getInstance().getRequestMap().get(threadId));
					}
				} else {
					Field connHandlerField = inputStream.getClass().getDeclaredField(FIELD_CONN_HANDLER);
					connHandlerField.setAccessible(true);
					Object connHandler = connHandlerField.get(inputStream);

					Field bufField = connHandler.getClass().getDeclaredField(BYTE_BUFFER_FIELD_BUF);
					bufField.setAccessible(true);
					byte[] buf = (byte[]) bufField.get(connHandler);

					Field posField = connHandler.getClass().getDeclaredField(FIELD_POS);
					posField.setAccessible(true);
					Integer pos = (Integer) posField.get(connHandler);

					servletInfo.setRawRequest(new String(buf, 0, pos, StandardCharsets.UTF_8));

					servletInfo.addGenerationTime((int) (System.currentTimeMillis() - start));
					if (!ServletEventPool.getInstance().getRequestMap().containsKey(threadId)) {
						ConcurrentLinkedDeque<ExecutionMap> executionMaps = new ConcurrentLinkedDeque<ExecutionMap>();
						executionMaps.add(new ExecutionMap(executionId, servletInfo));
						ServletEventPool.getInstance().getRequestMap().put(threadId, executionMaps);

					} else {
						servletInfo.addGenerationTime((int) (System.currentTimeMillis() - start));
						ServletEventPool.getInstance().getRequestMap().get(threadId)
								.add(new ExecutionMap(executionId, servletInfo));
					}
				}

			} catch (Exception e) {
				logger.log(LogLevel.WARNING, "Exception occured in WEBLOGIC_INVOKE_SERVLET buffer processing : ", e,
						LoggingInterceptor.class.getName());
//				e.printStackTrace();
			}
		} else {
//			 logger.log(LogLevel.INFO, "ServletEventPool.getInstance().getRequestMap() : "+ ServletEventPool.getInstance().getRequestMap(), LoggingInterceptor.class.getName());
			try {
				if (MYSQL_SOURCE_METHOD_LIST.contains(sourceString) && arg[0] != null) {
					processMysqlStatement(arg, threadId, sourceString);
				}
				if (ServletEventPool.getInstance().getRequestMap().containsKey(threadId) && ExecutionMap
						.find(executionId, ServletEventPool.getInstance().getRequestMap().get(threadId)) != null) {
//					logger.log(LogLevel.INFO, "Other event : source : "+ sourceString, LoggingInterceptor.class.getName());

					if (FILE_EXECUTORS.containsKey(sourceString)) {
						checkForFileIntegrityVoilations(arg, ExecutionMap.find(executionId,
								ServletEventPool.getInstance().getRequestMap().get(threadId)));
					}

					ServletEventPool.getInstance().incrementServletInfoReference(threadId, executionId, true);
					EventThreadPool.getInstance().processReceivedEvent(source, arg, executionId,
							Thread.currentThread().getStackTrace(), threadId, sourceString,
							System.currentTimeMillis() - start, ExecutionMap.find(executionId,
									ServletEventPool.getInstance().getRequestMap().get(threadId)));

				}
			} catch (Exception e) {
				logger.log(LogLevel.WARNING, "Exception occured in Other event processing : ", e,
						LoggingInterceptor.class.getName());
			}

		}

	}

	private String getRemoteAddressForWebsphere(Object arg, String sourceString) {
		String remoteAddress = null;
		try {
			Object thisPointer = arg;
			ClassLoader currentClassLoader = thisPointer.getClass().getClassLoader();
			Method getVirtualConnectionMethod;
			if(sourceString.equals(WEBSPHERE_LIBERTY_PROCESSREQUEST))
				getVirtualConnectionMethod = Class.forName(COM_IBM_WS_HTTP_CHANNEL_INTERNAL_INBOUND_HTTP_INBOUND_LINK, true, currentClassLoader).getDeclaredMethod(METHOD_GET_VIRTUAL_CONNECTION);
			else
				getVirtualConnectionMethod = Class.forName(COM_IBM_WS_HTTP_CHANNEL_INBOUND_HTTP_INBOUND_LINK, true, currentClassLoader).getDeclaredMethod(METHOD_GET_VIRTUAL_CONNECTION);
			Object virtualConnectionObj = getVirtualConnectionMethod.invoke(thisPointer);

			Method getConnectionDescriptorMethod = Class.forName(COM_IBM_WSSPI_CHANNELFW_VIRTUAL_CONNECTION, true, currentClassLoader).getDeclaredMethod(METHOD_GET_CONNECTION_DESCRIPTOR);
			Object connectionDescObj = getConnectionDescriptorMethod.invoke(virtualConnectionObj);

			Method getRemoteHostAddressMethod = Class.forName(COM_IBM_WSSPI_CHANNELFW_CONNECTION_DESCRIPTOR, true, currentClassLoader).getDeclaredMethod(METHOD_GET_REMOTE_HOST_ADDRESS);
			remoteAddress = (String) getRemoteHostAddressMethod.invoke(connectionDescObj);

			} catch (Exception ex) {
				logger.log(LogLevel.ERROR, "Error getting remote address : "+ex.getMessage(), LoggingInterceptor.class.getName());
			}
		return remoteAddress;
	}

	private String getRemoteAddressForWildfly(Object arg) {
		String remoteAdderss = null;
		try {
			Object exchangeObj = arg;
			ClassLoader currentClassLoader = exchangeObj.getClass().getClassLoader();

			Field connectionField = exchangeObj.getClass().getDeclaredField(FIELD_CONNECTION);
			connectionField.setAccessible(true);
			Object connectionObj = connectionField.get(exchangeObj);

			Field oscField = connectionObj.getClass().getSuperclass().getDeclaredField(FIELD_ORIGINAL_SOURCE_CONDUIT);
			oscField.setAccessible(true);
			Object oscObj = oscField.get(connectionObj);

			if (Class.forName(ORG_XNIO_NIO_NIO_SOCKET_CONDUIT, true, currentClassLoader).isInstance(oscObj)) {
				Field socketChannelField = oscObj.getClass().getDeclaredField(FIELD_SOCKET_CHANNEL);
				socketChannelField.setAccessible(true);
				SocketChannel socketChannelObj = (SocketChannel) socketChannelField.get(oscObj);

				SocketAddress socketAddressObj = socketChannelObj.getRemoteAddress();
				if (socketAddressObj instanceof InetSocketAddress) {
					InetSocketAddress isa = (InetSocketAddress)socketAddressObj;
					InetAddress address = isa.getAddress();
					remoteAdderss = address.getHostAddress();
				} else {
					logger.log(LogLevel.INFO, "socketAddressObj not instance of InetSocketAddress, need to handle other cases", LoggingInterceptor.class.getName());
				}
			} else {
				logger.log(LogLevel.INFO, "originalSourceConduit not instance of NioSocketConduit, need to handle other cases", LoggingInterceptor.class.getName());
			}

			} catch (Throwable ex) {
				System.out.println(ex.getMessage());
				ex.printStackTrace(System.err);
			}
		return remoteAdderss;
	}

	private static String getFileExtension(File file) {
		String fileName = file.getName();
		if (fileName.lastIndexOf(".") != -1 && fileName.lastIndexOf(".") != 0)
			return fileName.substring(fileName.lastIndexOf(".") + 1);
		else
			return StringUtils.EMPTY;
	}

	private void checkForFileIntegrityVoilations(Object[] arg, HttpRequestBean httpRequestBean) {
		try {
			File file = Paths.get(arg[0].toString()).toFile();
			String extension = getFileExtension(file);
			if (SOURCE_EXENSIONS.contains(extension)) {
				httpRequestBean.getFileExist().put(file.getAbsolutePath(), new FileIntegrityBean(file.exists()));
			}
		} catch (Exception e) {
			logger.log(LogLevel.ERROR, StringUtils.EMPTY, e, LoggingInterceptor.class.getName());
		}
	}

	private void updateThreadMaps(long threadId, Long executionId, Long newThreadId, int i) {
		Pair<Long, Long> pairedKey = new ImmutablePair<>(threadId, executionId - i);
//		System.out.println("Fetching for pair : "+ threadId+" AND "+ (executionId - i));
//		System.out.println("Present is : "+ ThreadMapping.getInstance().getTempThreadRequestMap());
		ConcurrentLinkedDeque<ThreadRequestData> threadRequestData = ThreadMapping.getInstance()
				.getTempThreadRequestMap().get(pairedKey);
//		ThreadMapping.getInstance().getTempThreadRequestMap().remove(pairedKey);
		if (threadRequestData != null) {
			if (!ThreadMapping.getInstance().getMappedThreadRequestMap().containsKey(newThreadId))
				ThreadMapping.getInstance().getMappedThreadRequestMap().put(newThreadId,
						new ConcurrentLinkedDeque<ThreadRequestData>());
			ThreadMapping.getInstance().getMappedThreadRequestMap().get(newThreadId).addAll(threadRequestData);
		}
	}

	private String fetchRequestStringForWildfly(Object buffer, ClassLoader currentClassLoader) {
		String requestData = EMPTY;
		try {
			Field limitField = Class.forName(JAVA_NIO_BUFFER, true, currentClassLoader).getDeclaredField(FIELD_LIMIT);
			limitField.setAccessible(true);
			int limit = (int) limitField.get(buffer);
			byte[] bytesObtained = new byte[limit];
			Class[] paramInt = new Class[1];
			paramInt[0] = Integer.TYPE;
			Method getByIndexMethod = Class.forName(JAVA_NIO_DIRECT_BYTE_BUFFER, true, currentClassLoader)
					.getDeclaredMethod(FIELD_GET, paramInt);
			for (int i = 0; i < limit; i++) {
				getByIndexMethod.setAccessible(true);
				byte bb = (byte) getByIndexMethod.invoke(buffer, i);
				bytesObtained[i] = bb;
			}
			requestData = new String(bytesObtained);
//			System.out.println("Data finally obtained : " + requestData);
//			logger.log(LogLevel.DEBUG, requestData, LoggingInterceptor.class.getName());
		} catch (Exception e) {
			logger.log(LogLevel.WARNING, "Exception occured in fetchRequestStringForWildfly : ", e,
					LoggingInterceptor.class.getName());
		}
		return requestData;
	}

	@Override
	protected void doOnThrowableThrown(Object source, Throwable throwable, String executionId) {
//		String sourceString = null;
//		long threadId = Thread.currentThread().getId();
//		if (source instanceof Method) {
//			sourceString = ((Method) source).toGenericString();
//
//		} else if (source instanceof Constructor) {
//			sourceString = ((Constructor) source).toGenericString();
//		} else {
//			return;
//		}
//		System.out.println("doOnThrowableThrown Executionid: " + executionId);
//		System.out.println("doOnThrowableThrown Thread Id: " + threadId);
//		System.out.println("doOnThrowableThrown SourceString: " + sourceString);

		onTerminationOfHookedMethods(source, executionId);
	}

	@Override
	protected void doOnThrowableUncatched(Object source, Throwable throwable, String executionId) {
//		String sourceString = null;
//		long threadId = Thread.currentThread().getId();
//		if (source instanceof Method) {
//			sourceString = ((Method) source).toGenericString();
//
//		} else if (source instanceof Constructor) {
//			sourceString = ((Constructor) source).toGenericString();
//		} else {
//			return;
//		}
//		System.out.println("doOnThrowableUncatched Executionid: " + executionId);
//		System.out.println("doOnThrowableUncatched Thread Id: " + threadId);
//		System.out.println("doOnThrowableUncatched SourceString: " + sourceString);

		onTerminationOfHookedMethods(source, executionId);
	}

	@Override
	protected void doOnFinish(Object[] args, Object source, Object result, String eId) {

		String sourceString = null;
		long threadId = Thread.currentThread().getId();
		if (source instanceof Method) {
			sourceString = ((Method) source).toGenericString();

		} else if (source instanceof Constructor) {
			sourceString = ((Constructor) source).toGenericString();
		} else {
			return;
		}
//		System.out.println("end Executionid: " + eId);
//		System.out.println("end Thread Id: " + threadId);
//		System.out.println("end SourceString: " + sourceString);
		Long executionId = Long.parseLong(eId.split(COLON_SEPERATOR)[1]);
//		logger.log(LogLevel.INFO, "OnFinish source: " + sourceString +  " :: eid: " + eId,LoggingInterceptor.class.getName());

//		if(sourceString.equals("private static synchronized long java.lang.Thread.nextThreadID()")) {
//			long threadIdCreated = (long) result;
//			System.out.println("Created Thread's id ::: "+ threadIdCreated);
//			System.out.println("We should map : "+threadId+" to : "+ threadIdCreated);
//			for(StackTraceElement tr : Thread.currentThread().getStackTrace()) {
//				System.out.println("CN : "+ tr.getClassName() + "." + tr.getMethodName()+" :: LN : "+ tr.getLineNumber());
//			}
//			System.out.println("");
//		}
		if (sourceString.equals(PUBLIC_VOID_ORG_XNIO_XNIO_WORKER_EXECUTE_JAVA_LANG_RUNNABLE) || sourceString
				.equals(PRIVATE_INT_ORG_JBOSS_THREADS_ENHANCED_QUEUE_EXECUTOR_TRY_EXECUTE_JAVA_LANG_RUNNABLE)) {
			int decreament;
			if (sourceString
					.equals(PRIVATE_INT_ORG_JBOSS_THREADS_ENHANCED_QUEUE_EXECUTOR_TRY_EXECUTE_JAVA_LANG_RUNNABLE))
				decreament = 2;
			else
				decreament = 1;
			Pair<Long, Long> oldPairedKey = new ImmutablePair<Long, Long>(threadId, executionId - decreament);
			if (ThreadMapping.getInstance().getMappedThreadIDToRemove().containsKey(oldPairedKey)) {
				ThreadMapping.getInstance().getMappedThreadIDToRemove().remove(oldPairedKey);
				ThreadMapping.getInstance().getTempThreadRequestMap().remove(oldPairedKey);
			}
		}
		if (sourceString.equals(
				PUBLIC_JAVA_LANG_THREAD_ORG_XNIO_XNIO_WORKER$_WORKER_THREAD_FACTORY_NEW_THREAD_JAVA_LANG_RUNNABLE)) {
			Thread returnedThread = (Thread) result;
			Long newThreadId = returnedThread.getId();
//			System.out.println("Created Thread's id ::: " + newThreadId);
//			System.out.println("We should map : "+threadId+" to : "+ newThreadId);
//			if(oldWildfly)
//				updateThreadMaps(threadId, executionId, newThreadId, 1);
//			else
			Pair<Long, Long> oldPairedKey;
			if (isOldWildfly) {
				oldPairedKey = new ImmutablePair<Long, Long>(threadId, executionId - 2);

//			System.out.println("HereMappedThreadIDToRemove" + ThreadMapping.getInstance().getMappedThreadIDToRemove());
				if (ThreadMapping.getInstance().getMappedThreadIDToRemove().containsKey(oldPairedKey)) {
					ThreadMapping.getInstance().getMappedThreadRequestMap()
							.remove(ThreadMapping.getInstance().getMappedThreadIDToRemove().get(oldPairedKey));
					ThreadMapping.getInstance().getMappedThreadIDToRemove().remove(oldPairedKey);
				}
			} else {
				oldPairedKey = new ImmutablePair<Long, Long>(threadId, executionId - 3);
			}
			if (isOldWildfly)
				updateThreadMaps(threadId, executionId, newThreadId, 2);
			else
				updateThreadMaps(threadId, executionId, newThreadId, 3);
			ThreadMapping.getInstance().getTempThreadRequestMap().remove(oldPairedKey);
//			System.out.println("Updated : "+ ThreadMapping.getInstance().getMappedThreadRequestMap());

		} else if (sourceString.equals(WEBSPHERE_LIBERTY_FILLBYTECACHE)
				|| sourceString.equals(WEBSPHERE_TRADITIONAL_FILLBYTECACHE)) {
			if (args.length == 0)
				return;
			Object arg = args[args.length - 1];
			Object thisPointer = arg;
			ClassLoader currentClassLoader = arg.getClass().getClassLoader();
			try {
				Class<?> BNFHeadersImpl = null;
				if (sourceString.equals(WEBSPHERE_LIBERTY_FILLBYTECACHE))
					BNFHeadersImpl = Class.forName(CLASS_COM_IBM_WS_GENERICBNF_INTERNAL_BNF_HEADERS_IMPL, true,
							currentClassLoader);
				else if (sourceString.equals(WEBSPHERE_TRADITIONAL_FILLBYTECACHE))
					BNFHeadersImpl = Class.forName(CLASS_COM_IBM_WS_GENERICBNF_IMPL_BNF_HEADERS_IMPL, true,
							currentClassLoader);
				else
					return;
				Field byteCacheField = BNFHeadersImpl.getDeclaredField(BYTE_CACHE);
				byteCacheField.setAccessible(true);
				byte[] bytes = (byte[]) byteCacheField.get(thisPointer);

				Field byteLimitField = BNFHeadersImpl.getDeclaredField(BYTE_LIMIT);
				byteLimitField.setAccessible(true);
				int byteLimit = (int) byteLimitField.get(thisPointer);

				String requestContent = new String(bytes, 0, byteLimit, StandardCharsets.UTF_8);
				HttpRequestBean servletInfo = ExecutionMap.find(executionId,
						ServletEventPool.getInstance().getRequestMap().get(threadId));
				if (servletInfo.getRawRequest() == null) {
					servletInfo.setRawRequest(requestContent);
				} else if (servletInfo.getRawRequest().length() > 8192 || servletInfo.isDataTruncated()) {
					servletInfo.setDataTruncated(true);
				} else {
					servletInfo.setRawRequest(servletInfo.getRawRequest() + requestContent);
				}

			} catch (Exception e) {
				logger.log(LogLevel.SEVERE, "Exception occured in fetching information for Websphere: ", e,
						LoggingInterceptor.class.getName());
			}

		} else {
			onTerminationOfHookedMethods(source, eId);
		}
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
				logger.log(LogLevel.WARNING, "Exception occured in processMysqlStatement CONNECTOR_5: ", e,
						LoggingInterceptor.class.getName());
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
				logger.log(LogLevel.WARNING, "Exception occured in processMysqlStatement CONNECTOR_6 : ", e,
						LoggingInterceptor.class.getName());
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
				logger.log(LogLevel.WARNING, "Exception occured in processMysqlStatement CONNECTOR_8 : ", e,
						LoggingInterceptor.class.getName());
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
			logger.log(LogLevel.INFO,
					TOMCAT_VERSION_DETECTED_MSG + tomcatMajorVersion + COLON_SEPERATOR + tomcatVersion,
					LoggingInterceptor.class.getName());

		} catch (Exception e) {
			logger.log(LogLevel.WARNING, "Unable to find Tomcat Version: ", e, LoggingInterceptor.class.getName());
		}
	}

	public static void shutdownLogic(Runtime runtime, final ClassFileTransformer classTransformer) {
		ShutDownEvent shutDownEvent = new ShutDownEvent();
		shutDownEvent.setApplicationUUID(Agent.APPLICATION_UUID);
		shutDownEvent.setStatus("Terminating");
		EventSendPool.getInstance().sendEvent(shutDownEvent.toString());
		logger.log(LogLevel.INFO, "Shutting down with status: " + shutDownEvent, LoggingInterceptor.class.getName());
		try {
			TimeUnit.SECONDS.sleep(1);
		} catch (InterruptedException e) {
		}
		try {
			WSClient.getInstance().close();
		} catch (URISyntaxException | InterruptedException e) {
		}
		ServletEventPool.getInstance().shutDownThreadPoolExecutor();
		IPScheduledThread.getInstance().shutDownThreadPoolExecutor();
		Agent.globalInstr.removeTransformer(classTransformer);
		retransformHookedClassesWrapper();
		logger.log(LogLevel.SEVERE, "Java Agent shutdown complete.", LoggingInterceptor.class.getName());
	}

	@Override
	public boolean addShutDownHook(final Runtime runtime, final ClassFileTransformer classTransformer) {
		FileWatcher.getInstance().setClassTransformer(classTransformer);
		FileWatcher.getInstance().setRuntime(runtime);
//		try {
//			FileWatcher.getInstance().watchDirectory("/etc/k2-adp");
//		} catch (IOException e) {
//			logger.log(LogLevel.SEVERE, e.toString());
//		}
		runtime.addShutdownHook(new Thread() {
			@Override
			public void run() {
				shutdownLogic(runtime, classTransformer);
			}
		});
		return false;
	}

	@Override
	protected List<String> getClassesToLoad() {
		return new ArrayList<String>(IAgentConstants.INSTRUMENTED_METHODS.keySet());
	}

	private static void retransformHookedClassesWrapper() {
		List<String> classesToRetransform = new ArrayList<String>(IAgentConstants.INSTRUMENTED_METHODS.keySet());

		Map<String, Class<?>> allLoadedClasses = new HashMap<>();

		for (Class<?> cls : Agent.globalInstr.getAllLoadedClasses()) {
			allLoadedClasses.put(cls.getName(), cls);
		}

		for (String loadedClass : classesToRetransform) {
			String loadedClassName = loadedClass.replaceAll("/", STRING_DOT);
			try {
				Class<?> cl = allLoadedClasses.get(loadedClassName);
				if (cl == null) {
					continue;
				}
				Agent.globalInstr.retransformClasses(cl);
			} catch (Exception e) {
				logger.log(LogLevel.ERROR, "Error while retransforming class : " + loadedClassName, e,
						LoggingInterceptor.class.getName());
			}
		}
	}

	@Override
	public void retransformHookedClasses() {
		retransformHookedClassesWrapper();
	}

	private Object getNextQnode(Object tailObject, ClassLoader currentClassLoader) {
		Field nextField;
		Object nextObject = null;
		try {
			nextField = Class.forName(ORG_JBOSS_THREADS_ENHANCED_QUEUE_EXECUTOR$Q_NODE, true, currentClassLoader)
					.getDeclaredField(FIELD_NEXT);
			nextField.setAccessible(true);
			nextObject = nextField.get(tailObject);
		} catch (NoSuchFieldException | SecurityException | ClassNotFoundException | IllegalArgumentException
				| IllegalAccessException e) {
			logger.log(LogLevel.ERROR, "Error in getNextQnode : ", e, LoggingInterceptor.class.getName());
		}
		return nextObject;

	}

//	private Object getNextTail(Object tailObject, ClassLoader currentClassLoader) {
//		Field tailField = Class.forName("org.jboss.threads.EnhancedQueueExecutor", true, currentClassLoader).getDeclaredField("tail");
//		tailField.setAccessible(true);
//		Object tailObject = tailField.get(tailObject);
//	}

}
