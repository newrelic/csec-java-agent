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

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.Socket;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.brutusin.instrumentation.Agent;
import org.brutusin.instrumentation.Interceptor;
import org.json.simple.JSONArray;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

public class LoggingInterceptor extends Interceptor {

	private static final Set<String> allClasses;
	private static final Map<String, List<String>> interceptMethod;
	protected static DataOutputStream oos;
	protected static Integer VMPID;
	protected static final String applicationUUID;
	protected static Socket socket;
	static final int MAX_DEPTH_LOOKUP = 4; // Max number of superclasses to lookup for a field
	// protected static Map<Long, ServletInfo> requestMap;
	protected static ScheduledExecutorService eventPoolExecutor;

	static {
		applicationUUID = UUID.randomUUID().toString();
		allClasses = new HashSet<>(Arrays.asList(IAgentConstants.ALL_CLASSES));
		interceptMethod = new HashMap<>();
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
					return st.substring(st.lastIndexOf('/') + 1);
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
	 * Method to poll for Agent.getJarPathResultExecutorService to complete
	 * jarPathSet population & then create & send desired JarPathBean .
	 */
	public static void getJarPath() {
		Runnable jarPathPool = new Runnable() {
			public void run() {
				System.out.println("Pooling getJarPathResultExecutorService to fetch results.");
				try {
					if (Agent.getJarPathResultExecutorService.awaitTermination(5, TimeUnit.MINUTES)) {
						if (!Agent.jarPathSet.isEmpty()) {
							JarPathBean jarPathBean = new JarPathBean(applicationUUID,
									new ArrayList<String>(Agent.jarPathSet));
							String containerId = getContainerID();
							if (containerId != null) {
								jarPathBean.setIsHost(false);
							} else
								jarPathBean.setIsHost(true);
							try {
								oos.writeUTF(jarPathBean.toString());
								// oos.flush();
								/*
								 * writer.write(jarPathBean.toString()); writer.flush();
								 */
							} catch (IOException e) {
								System.out.println("Error in writing: " + e.getMessage());
								try {
									LoggingInterceptor.oos.close();
								} catch (IOException e1) {
									LoggingInterceptor.socket = null;
								}
							}
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

	public static void createApplicationInfoBean() throws IOException {
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
		// applicationInfoBean.setJvmArguments(new
		// JSONArray(runtimeMXBean.getInputArguments()));
		JSONArray jsonArray = new JSONArray();
		jsonArray.addAll(cmdlineArgs);
		applicationInfoBean.setJvmArguments(jsonArray);
		oos.writeUTF(applicationInfoBean.toString());
		System.out.println("application info posted : " + applicationInfoBean);
		oos.flush();
	}

	protected static void connectSocket() {
		try (BufferedReader reader = new BufferedReader(new FileReader("/etc/k2-adp/hostip.properties"))) {
			String hostip = reader.readLine();
			if (hostip == null || hostip.equals(""))
				throw new RuntimeException("Host ip not found");
			System.out.println("hostip found: " + hostip);
			socket = new Socket(hostip, 54321);
			if (!socket.isConnected() || socket.isClosed())
				throw new RuntimeException("Can't connect to IC, agent installation failed.");
			oos = new DataOutputStream(socket.getOutputStream());
		} catch (Exception e) {
			throw new RuntimeException(e);
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
		try {
			connectSocket();
			getJarPath();
			createApplicationInfoBean();
			eventWritePool();
			System.out.println("K2-JavaAgent installed successfully.");

		} catch (Exception e) {
			System.err.println("Can't connect to IC, agent installation failed.");
		}
	}

	private static void eventWritePool() {
		eventPoolExecutor = Executors.newScheduledThreadPool(1);
		eventPoolExecutor.scheduleWithFixedDelay(new Runnable() {
			@Override
			public void run() {
				if (!ProcessorThread.eventQueue.isEmpty()) {
					ProcessorThread.queuePooler();
				}
			}
		}, 2, 2, TimeUnit.SECONDS);
	}

	private static String getCmdLineArgsByProc(Integer pid) {
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
//		System.out.println("class came to instument : "+className);
//		if (className.startsWith("org/hsqldb/")) {
//			System.out.println("class to instument : "+className);
//			return true;
//		}

		return allClasses.contains(className);
	}

	public org.brutusin.instrumentation.logging.ByteBuffer preProcessTomcatByteBuffer(byte[] buffer, int limitHb) {
		byte[] modifiedBuffer = new byte[limitHb];
		modifiedBuffer[0] = buffer[0];
		int k = 1;
		for (int i = 1; i < limitHb - 2; i++) {
			if (buffer[i + 1] == 13 && buffer[i + 2] == 10 && i + 4 <= limitHb && buffer[i + 3] == 13
					&& buffer[i + 4] == 10) {
				while (i < limitHb) {
					modifiedBuffer[k] = buffer[i];
					i++;
					k++;
				}
				return new org.brutusin.instrumentation.logging.ByteBuffer(modifiedBuffer, k);
			}
			if (buffer[i + 1] == 13 && buffer[i + 2] == 10 && buffer[i - 1] == buffer[i]) {

			} else {
				modifiedBuffer[k] = buffer[i];
				k++;
			}
		}
		modifiedBuffer[k++] = 13;
		modifiedBuffer[k++] = 10;
		return new org.brutusin.instrumentation.logging.ByteBuffer(modifiedBuffer, k);
	}

	@Override
	public boolean interceptMethod(ClassNode cn, MethodNode mn) {
		// if
		// (cn.name.equals("org/apache/struts2/dispatcher/ng/filter/StrutsPrepareAndExecuteFilter"))
		// System.out.println("name: " + mn.name + " : " +
		// interceptMethod.get(cn.name).contains(mn.name));
		// else if (cn.name.equals("javax/faces/webapp/FacesServlet"))
		// System.out.println("name: " + mn.name + " : " +
		// interceptMethod.get(cn.name).contains(mn.name));
//		if (cn.name.startsWith("org/hsqldb/")) {
//			System.err.println("Agent instrumenting : " + cn.name + " : " + mn.name);
//			return true;
//		}
		return interceptMethod.get(cn.name).contains(mn.name);
	}

	private void onTerminationOfHookedMethods(Object source) {
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
			if (sourceString != null && (IAgentConstants.TOMCAT_COYOTE_ADAPTER_SERVICE.equals(sourceString)
					|| IAgentConstants.JETTY_REQUEST_HANDLE.equals(sourceString))) {
				if (ServletEventPool.getInstance().decrementServletInfoReference(threadId) <= 0) {
					// System.out.println("Request map entry removed for threadID " + threadId);
					// System.out.println("Current request map : " +
					// ServletEventPool.getInstance().getRequestMap());
//					 System.out.println(threadId + ":: remove from coyote");
					ServletEventPool.getInstance().getRequestMap().remove(threadId);
				}
			}
		}
	}

	@SuppressWarnings({ "rawtypes" })
	@Override
	protected void doOnStart(Object source, Object[] arg, String executionId) {
		String sourceString = null;

		long threadId = Thread.currentThread().getId();
		// System.out.println("Thread Id: " + threadId);
		if (source instanceof Method) {
			sourceString = ((Method) source).toGenericString();

		} else if (source instanceof Constructor) {
			sourceString = ((Constructor) source).toGenericString();
		} else {
			return;
		}
//		System.out.println( ": " +sourceString);
//		 System.out.println("doOnStart : " + threadId+" : " + sourceString);

		if (sourceString == null)
			return;

		if (IAgentConstants.JETTY_REQUEST_HANDLE.equals(sourceString)) {
			ServletEventPool.getInstance().incrementServletInfoReference(threadId);
		} else if (IAgentConstants.JETTY_PARSE_NEXT.equals(sourceString)) {

			ServletInfo servletInfo;

			if (!ServletEventPool.getInstance().getRequestMap().containsKey(threadId)) {
				servletInfo = new ServletInfo();
				ServletEventPool.getInstance().getRequestMap().put(threadId, servletInfo);
			}
			servletInfo = ServletEventPool.getInstance().getRequestMap().get(threadId);
			try {
				String requestContent = null;
				Field limit = Buffer.class.getDeclaredField("limit");
				limit.setAccessible(true);
				Field positionField = Buffer.class.getDeclaredField("position");
				positionField.setAccessible(true);
				int positionHb = (Integer) positionField.get(arg[0]);
				int limitHb = (Integer) limit.get(arg[0]);
				if (limitHb > 0 && positionHb == 0) {

					Field hb = ByteBuffer.class.getDeclaredField("hb");
					hb.setAccessible(true);
					byte[] hbContent = (byte[]) hb.get(arg[0]);

					requestContent = new String(hbContent, 0, limitHb, StandardCharsets.UTF_8);
					if (servletInfo.getRawRequest().length() > 8192 || servletInfo.isDataTruncated()) {
						servletInfo.setDataTruncated(true);
					} else {
						servletInfo.setRawRequest(servletInfo.getRawRequest() + requestContent);
					}
					// System.out.println("Request Param : " + servletInfo);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else if (IAgentConstants.TOMCAT_SETBYTEBUFFER.equals(sourceString)) {
			ServletInfo servletInfo;
			if (!ServletEventPool.getInstance().getRequestMap().containsKey(threadId)) {
				servletInfo = new ServletInfo();
				ServletEventPool.getInstance().getRequestMap().put(threadId, servletInfo);
			}
			servletInfo = ServletEventPool.getInstance().getRequestMap().get(threadId);
			try {
				String requestContent = null;
				Field limit = Buffer.class.getDeclaredField("limit");
				limit.setAccessible(true);
				Field positionField = Buffer.class.getDeclaredField("position");
				positionField.setAccessible(true);
				int positionHb = (Integer) positionField.get(arg[0]);

				int limitHb = (Integer) limit.get(arg[0]);
				if (limitHb > 0) {

					Field hb = ByteBuffer.class.getDeclaredField("hb");
					hb.setAccessible(true);
					byte[] hbContent = (byte[]) hb.get(arg[0]);

					requestContent = new String(hbContent, positionHb, limitHb - positionHb, StandardCharsets.UTF_8);
					if (servletInfo.getRawRequest().length() > 8192 || servletInfo.isDataTruncated()) {
						servletInfo.setDataTruncated(true);
					} else {
						servletInfo.setRawRequest(servletInfo.getRawRequest() + requestContent);
					}
					// System.out.println("Request Param : " + servletInfo);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else if (IAgentConstants.TOMCAT_COYOTE_ADAPTER_SERVICE.equals(sourceString)) {
			// System.out.println("RequestMap : " +
			// ServletEventPool.getInstance().getRequestMap());
			// System.out.println("RequestMapRef : " +
			// ServletEventPool.getInstance().getServletInfoReferenceRecord());
			// System.out.println("Coyote Service: " + threadId + " : " + sourceString);
			ServletEventPool.getInstance().incrementServletInfoReference(threadId);
			ServletInfo servletInfo = new ServletInfo();
			ServletEventPool.getInstance().getRequestMap().put(threadId, servletInfo);
			try {
				String requestContent = null;

				Field inputBufferField = arg[0].getClass().getDeclaredField("inputBuffer");
				inputBufferField.setAccessible(true);
				Object inputBuffer = inputBufferField.get(arg[0]);
				Object byteBuffer = null;
				int positionHb = -1;
				boolean byteBufferFound = false;
				boolean tomcatv7 = false;
				try {
					Field byteBufferField = inputBuffer.getClass().getDeclaredField("byteBuffer");
					byteBufferField.setAccessible(true);
					byteBuffer = byteBufferField.get(inputBuffer);

					Field position = Buffer.class.getDeclaredField("position");
					position.setAccessible(true);
					positionHb = (Integer) position.get(byteBuffer);
					byteBufferFound = true;
				} catch(Exception e) {
					e.printStackTrace();
				}
				if(!byteBufferFound) {
					try {
						Class<?> abstractInputBufferClass = Class.forName("org.apache.coyote.http11.AbstractInputBuffer", true, Thread.currentThread().getContextClassLoader());
						Field byteBufferField = abstractInputBufferClass.getDeclaredField("buf");
						byteBufferField.setAccessible(true);
						byteBuffer = byteBufferField.get(inputBuffer);
	
						Field position = abstractInputBufferClass.getDeclaredField("lastValid");
						position.setAccessible(true);
						positionHb = (Integer) position.get(inputBuffer);
						if(positionHb == 8192) {
							servletInfo.setDataTruncated(true);
						}
						tomcatv7 = true;
						byteBufferFound = true;
					} catch(Exception e) {
					}
				}

				if (byteBufferFound && positionHb > 0) {

					byte[] hbContent = null;
					
					if(!tomcatv7) {
						Field hb = ByteBuffer.class.getDeclaredField("hb");
						hb.setAccessible(true);
						hbContent = (byte[]) hb.get(byteBuffer);
					} else {
						hbContent = (byte[]) byteBuffer;
					}
					
					org.brutusin.instrumentation.logging.ByteBuffer buff = preProcessTomcatByteBuffer(hbContent,
							positionHb);
					requestContent = new String(buff.getByteArray(), 0, buff.getLimit(), StandardCharsets.UTF_8);
					servletInfo.setRawRequest(requestContent);
//					 System.out.println("Request Param : "+threadId + " : " + executionId +":" + servletInfo);
				}
			} catch (Exception e) {
			}
			// in case of executeInternal()
		} else {

			if (IAgentConstants.MYSQL_SOURCE_METHOD_LIST.contains(sourceString) && arg[0] != null) {
				processMysqlStatement(arg, threadId, sourceString);
			}

			// System.out.println("RequestMap : " +
			// ServletEventPool.getInstance().getRequestMap() );
			// System.out.println("RequestMapRef : " +
			// ServletEventPool.getInstance().getServletInfoReferenceRecord() );
//			System.out.println("Other event : " + threadId + " : " + executionId +":" + sourceString + " : " + arg[0] + " : " + arg[1] + " current request map : " + ServletEventPool.getInstance().getRequestMap());

			try {
				if (ServletEventPool.getInstance().getRequestMap().containsKey(threadId)) {
//					System.out.println("Calling processor thread : "+ threadId + " : " + executionId);
					ServletEventPool.getInstance().incrementServletInfoReference(threadId);
					EventThreadPool.getInstance().processReceivedEvent(source, arg, executionId,
							Thread.currentThread().getStackTrace(), threadId, sourceString);
				}
			} catch (Exception e) {
			}

		}
		// System.out.println("started sourceString : "+ sourceString);
	}

	@Override
	protected void doOnThrowableThrown(Object source, Throwable throwable, String executionId) {
		onTerminationOfHookedMethods(source);
	}

	@Override
	protected void doOnThrowableUncatched(Object source, Throwable throwable, String executionId) {
		onTerminationOfHookedMethods(source);
	}

	@Override
	protected void doOnFinish(Object source, Object result, String executionId) {
		onTerminationOfHookedMethods(source);
	}

	private void processMysqlStatement(Object[] args, long threadId, String sourceString) {
		Object obj = args[0];
		if (sourceString.equals(IAgentConstants.MYSQL_CONNECTOR_5_0_4_PREPARED_SOURCE)) {
			obj = args[args.length - 1];
		}
		Class<?> objClass = obj.getClass();

		if (objClass.getName().equals(IAgentConstants.MYSQL_PREPARED_STATEMENT_5)
				|| objClass.getName().equals(IAgentConstants.MYSQL_PREPARED_STATEMENT_5_0_4)
				|| objClass.getName().equals(IAgentConstants.MYSQL_PREPARED_STATEMENT_42)
				|| objClass.getName().equals(IAgentConstants.MYSQL_PREPARED_STATEMENT_4)) {
			try {
				objClass = Class.forName(IAgentConstants.MYSQL_PREPARED_STATEMENT_5, true,
						Thread.currentThread().getContextClassLoader());
				Field originalSqlField = objClass.getDeclaredField("originalSql");
				originalSqlField.setAccessible(true);
				String originalSql = (String) originalSqlField.get(obj);

				// compute id and push in map
				String id = threadId + ":" + obj.hashCode();
				EventThreadPool.getInstance().setMySqlPreparedStatementsMap(id, originalSql);

			} catch (Exception e) {
				e.printStackTrace();
			}
		} else if (objClass.getName().equals(IAgentConstants.MYSQL_PREPARED_STATEMENT_6)
				&& (sourceString.equals(IAgentConstants.MYSQL_CONNECTOR_6_SOURCE)
						|| sourceString.equals(IAgentConstants.MYSQL_CONNECTOR_6_0_2_SOURCE)
						|| sourceString.equals(IAgentConstants.MYSQL_CONNECTOR_6_0_3_SOURCE))) {
			try {
				Field originalSqlField = objClass.getDeclaredField("originalSql");
				originalSqlField.setAccessible(true);
				String originalSql = (String) originalSqlField.get(obj);

				// compute id and push in map
				String id = threadId + ":" + obj.hashCode();
				EventThreadPool.getInstance().setMySqlPreparedStatementsMap(id, originalSql);
			} catch (Exception e) {
				e.printStackTrace();
			}
		} else if (objClass.getName().equals(IAgentConstants.MYSQL_PREPARED_STATEMENT_8)
				&& sourceString.equals(IAgentConstants.MYSQL_CONNECTOR_8_SOURCE)) {
			try {
				Field queryField = objClass.getSuperclass().getDeclaredField("query");
				queryField.setAccessible(true);
				Object query = queryField.get(obj);
				if (query != null && query.getClass().getName().equals(IAgentConstants.MYSQL_PREPARED_QUERY_8)) {
					objClass = Class.forName(IAgentConstants.MYSQL_PREPARED_STATEMENT_SOURCE_8, true,
							Thread.currentThread().getContextClassLoader());
					Field originalSqlField = objClass.getDeclaredField("originalSql");
					originalSqlField.setAccessible(true);
					String originalSql = (String) originalSqlField.get(query);

					// compute id and push in map
					String id = threadId + ":" + obj.hashCode();
					EventThreadPool.getInstance().setMySqlPreparedStatementsMap(id, originalSql);
				}
			} catch (Exception e) {
				e.printStackTrace();
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
				fos.write("\n".getBytes());
			} finally {
				fos.close();
			}
		} catch (IOException ex) {
			throw new RuntimeException(ex);
		}
	}

}
