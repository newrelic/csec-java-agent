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
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
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

import com.k2.org.json.simple.JSONArray;
import com.k2.org.objectweb.asm.tree.ClassNode;
import com.k2.org.objectweb.asm.tree.MethodNode;

public class LoggingInterceptor extends Interceptor {

	// private File rootFile;
	private static final Set<String> allClasses;
	private static final Map<String, List<String>> interceptMethod;
	// protected static BufferedWriter writer;
	// private static UnixSocketChannel channel;
	protected static DataOutputStream oos;
	protected static Integer VMPID;
	protected static final String applicationUUID;
	protected static Socket socket;
	protected static Map<Long, ServletInfo> requestMap;

	static {
		applicationUUID = UUID.randomUUID().toString();
		allClasses = new HashSet<>(Arrays.asList(IAgentConstants.ALL_CLASSES));
		interceptMethod = new HashMap<>();
		for (int i = 0; i < IAgentConstants.ALL_METHODS.length; i++) {
			interceptMethod.put(IAgentConstants.ALL_CLASSES[i],
					new ArrayList<String>(Arrays.asList(IAgentConstants.ALL_METHODS[i])));
		}
		requestMap = new HashMap<>();
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
								oos.flush();
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
			if(!socket.isConnected() || socket.isClosed())
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
			System.out.println("K2-JavaAgent installed successfully.");

		} catch (Exception e) {
			System.err.println("Can't connect to IC, agent installation failed.");
		}
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
	
	private static String readCharBuffer(CharBuffer cb) {
		System.out.println("Object 1 : " + cb);
		System.out.println("Object 1 limit : " + cb.limit());
		System.out.println("remaining 1    "+cb.remaining());
		cb.rewind();
		StringBuffer stringBuffer = new StringBuffer(); 
		while(cb.remaining() > 0) {
			stringBuffer.append(cb.get());
		}
		cb.rewind();
		return stringBuffer.toString();
		
	}
	
	private static String readByteBuffer(ByteBuffer buffer) {
		int currPos = buffer.position();
		System.out.println("Object 2 : " + buffer);
		System.out.println("Object 2 limit : " + buffer.limit());
		System.out.println("remaining 2    "+ buffer.remaining());
		
//		buffer.rewind();
		StringBuffer stringBuffer = new StringBuffer(); 
		while(buffer.remaining() > 0) {
			stringBuffer.append((char)buffer.get());
		}
		buffer.position(currPos);
		return stringBuffer.toString();		
	}
	
	@Override
	public boolean interceptClass(String className, byte[] byteCode) {
		return allClasses.contains(className);
	}

	@Override
	public boolean interceptMethod(ClassNode cn, MethodNode mn) {
		if (cn.name.equals("javax/servlet/http/HttpServlet"))
			System.out.println("name: " + mn.name + " : " + interceptMethod.get(cn.name).contains(mn.name));
		return interceptMethod.get(cn.name).contains(mn.name);
	}

	@SuppressWarnings({ "rawtypes" })
	@Override
	protected void doOnStart(Object source, Object[] arg, String executionId) {
		String sourceString = null;
		Method m = null;
		if (source instanceof Method) {
			m = (Method) source;
			sourceString = m.toGenericString();
			System.out.println(m.toGenericString());
		}
		if (sourceString != null && IAgentConstants.HTTP_SERVLET_SERVICE.equals(sourceString)) {
			ServletInfo servletInfo = new ServletInfo();
			Object firstElement = arg[0];
			Method getParameterMap;
			
			ByteBuffer bb = null;
			CharBuffer cb = null;
			try {
				System.out.println("class "+firstElement.getClass());
				System.out.println("fields "+Arrays.asList(firstElement.getClass().getDeclaredFields()));
				getParameterMap = firstElement.getClass().getMethod("getParameterMap");
				Method getQueryString = firstElement.getClass().getMethod("getQueryString");
				Method getRemoteAddr = firstElement.getClass().getMethod("getRemoteAddr");
				Method getMethod = firstElement.getClass().getMethod("getMethod");
				// extract ByteBuffer into bb and cb
				Field requestField = firstElement.getClass().getDeclaredField("request");
				requestField.setAccessible(true);
				Object requestObj = requestField.get(firstElement);
				
				System.out.println("class 2"+requestObj.getClass());
				System.out.println("fields 2"+Arrays.asList(requestObj.getClass().getDeclaredFields()));
				
				Field inputBufferField = requestObj.getClass().getDeclaredField("inputBuffer");
				inputBufferField.setAccessible(true);
				Object inputBuffer = inputBufferField.get(requestObj);
				
				
				Field coyoteRequestField = inputBuffer.getClass().getDeclaredField("coyoteRequest");
				coyoteRequestField.setAccessible(true);
				Object coyoteRequest = coyoteRequestField.get(inputBuffer);
				
				Field coyoteInputBufferField = coyoteRequest.getClass().getDeclaredField("inputBuffer");
				coyoteInputBufferField.setAccessible(true);
				Object coyoteInputBuffer = coyoteInputBufferField.get(coyoteRequest);
				
				Field bytes = coyoteInputBuffer.getClass().getDeclaredField("byteBuffer");
				bytes.setAccessible(true);
				bb = (ByteBuffer) bytes.get(coyoteInputBuffer);
				
//				Field bytes = inputBuffer.getClass().getDeclaredField("bb");
//				bytes.setAccessible(true);
//				bb = (ByteBuffer) bytes.get(inputBuffer);
//				
//				
//				
//				Field chars = inputBuffer.getClass().getDeclaredField("cb");
//				chars.setAccessible(true);
//				cb = (CharBuffer) chars.get(inputBuffer);			
//				
				servletInfo.setParameters((Map<String, String[]>) getParameterMap.invoke(firstElement, null));
				servletInfo.setQueryString((String) getQueryString.invoke(firstElement, null));
				servletInfo.setSourceIp((String) getRemoteAddr.invoke(firstElement, null));
				servletInfo.setRequestMethod((String) getMethod.invoke(firstElement, null));

			} catch (NoSuchMethodException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SecurityException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalArgumentException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvocationTargetException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchFieldException e) {
				e.printStackTrace();
			}
			
			System.out.println("ByteBuffer out : " + readByteBuffer(bb));
//			System.out.println("CharBuffer out : " + readCharBuffer(cb));
			requestMap.put(Thread.currentThread().getId(), servletInfo);
			return;
		}
		EventThreadPool.getInstance().processReceivedEvent(source, arg, executionId,
				Thread.currentThread().getStackTrace(), Thread.currentThread().getId());
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
//		Constructor c = null;
//		if (source instanceof Method) {
//			m = (Method) source;
//			sourceString = m.toGenericString();
//			System.out.println(m.toGenericString());
//		} else if (source instanceof Constructor) {
//			c = (Constructor) source;
//			sourceString = c.toGenericString();
//			// System.out.println(c.toGenericString());
//		}
//		if (sourceString != null && IAgentConstants.HTTP_SERVLET_SERVICE.equals(sourceString)) {
//			Thread.currentThread().getId();
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

}
