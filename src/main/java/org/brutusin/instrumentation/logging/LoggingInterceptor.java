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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.brutusin.instrumentation.Agent;
import org.brutusin.instrumentation.Interceptor;

import com.k2.org.json.simple.JSONArray;
import com.k2.org.objectweb.asm.tree.ClassNode;
import com.k2.org.objectweb.asm.tree.MethodNode;

public class LoggingInterceptor extends Interceptor {

	private static final Set<String> allClasses;
	private static final Map<String, List<String>> interceptMethod;
	protected static DataOutputStream oos;
	protected static Integer VMPID;
	protected static final String applicationUUID;
	protected static Socket socket;
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
		applicationInfoBean.setJvmArguments(new JSONArray(cmdlineArgs));
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

	@Override
	public boolean interceptClass(String className, byte[] byteCode) {
		return allClasses.contains(className);
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
		return interceptMethod.get(cn.name).contains(mn.name);
	}

	@SuppressWarnings({ "rawtypes" })
	@Override
	protected void doOnStart(Object source, Object[] arg, String executionId) {
		String sourceString = null;
		Method m = null;
		Constructor c = null;
		long threadId = Thread.currentThread().getId();

		if (source instanceof Method) {
			m = (Method) source;
			sourceString = m.toGenericString();
		} else if (source instanceof Constructor) {
			c = (Constructor) source;
			sourceString = c.toGenericString();
		}

		// System.out.println("doOnStart : " + threadId+" : " + sourceString+" : " +
		// servletInfo);
		if (sourceString != null && IAgentConstants.TOMCAT_COYOTE_ADAPTER_PARSE_POST.equals(sourceString)) {
			ServletEventPool.getInstance().incrementServletInfoReference(threadId);
			// System.out.println("Coyote : " + threadId + " : " + sourceString + " : " +
			// servletInfo);
			ServletInfo servletInfo = new ServletInfo();

			try {
				Object secondElement = arg[1];
				Field facadeField = secondElement.getClass().getDeclaredField("facade");
				facadeField.setAccessible(true);
				Object facade = facadeField.get(secondElement);
				ServletEventPool.getInstance().getRequestMap().put(threadId, servletInfo);
				// if (facade == null) {
				// System.out.println("facade null");
				// return;
				// }
				// System.out.println("Coyote submitting : " + threadId + " : " + sourceString +
				// " : " + servletInfo);
				// System.out.println("Coyote Current request map : " + requestMap);
				ServletEventPool.getInstance().processReceivedEvent(arg[0], facade, servletInfo, sourceString,
						threadId);
			} catch (Exception e) {
			}
			// TODO add else if for jetty on http service method
		} else if (sourceString != null && IAgentConstants.TOMCAT_REQUEST_FACADE.equals(sourceString)
				&& ServletEventPool.getInstance().getRequestMap().containsKey(threadId)) {
			ServletEventPool.getInstance().processReceivedEvent(null, arg[0],
					ServletEventPool.getInstance().getRequestMap().get(threadId), sourceString, threadId);
		} else {
			// System.out.println("Other event : " + threadId + " : " + sourceString + " : "
			// + requestMap.get(threadId)
			// + " : " + arg[0] + " : " + arg[1]);
			// System.out.println("Other event current request map : " + requestMap);
			if (ServletEventPool.getInstance().getRequestMap().containsKey(threadId)) {
				ServletEventPool.getInstance().incrementServletInfoReference(threadId);
				EventThreadPool.getInstance().processReceivedEvent(source, arg, executionId,
						Thread.currentThread().getStackTrace(), threadId,
						new ServletInfo(ServletEventPool.getInstance().getRequestMap().get(threadId)));
			}
		}

		// System.out.println("started sourceString : "+ sourceString);
	}

	@Override
	protected void doOnThrowableThrown(Object source, Throwable throwable, String executionId) {
	}

	@Override
	protected void doOnThrowableUncatched(Object source, Throwable throwable, String executionId) {
	}

	@Override
	protected void doOnFinish(Object source, Object result, String executionId) {
		String sourceString = null;
		Method m = null;
		long threadId = Thread.currentThread().getId();

		if (source instanceof Method) {
			m = (Method) source;
			sourceString = m.toGenericString();
			if (sourceString != null && IAgentConstants.TOMCAT_COYOTE_ADAPTER_SERVICE.equals(sourceString)) {
				if ( ServletEventPool.getInstance().decrementServletInfoReference(threadId) <= 0 ) {
					ServletEventPool.getInstance().getRequestMap().remove(threadId);
				} 

				// System.out.println("Request map entry removed for threadID " + threadId);
				// System.out.println("Current request map : "+ requestMap);
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
