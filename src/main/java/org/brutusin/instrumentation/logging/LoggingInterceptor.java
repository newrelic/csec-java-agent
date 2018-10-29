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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import org.brutusin.commons.json.spi.JsonCodec;
import org.brutusin.instrumentation.Interceptor;

import com.k2.org.json.simple.JSONArray;
import com.k2.org.json.simple.JSONObject;
import com.k2.org.objectweb.asm.tree.ClassNode;
import com.k2.org.objectweb.asm.tree.MethodNode;

import jnr.unixsocket.UnixSocketAddress;
import jnr.unixsocket.UnixSocketChannel;

public class LoggingInterceptor extends Interceptor {

	private File rootFile;
	private static final Set<String> methodMap;
	private static final Set<String> allClasses;
	private static final Map<String, List<String>> interceptMethod;
	private static final Pattern PATTERN;
	private static final Set<String> executorMathods;
	private static JSONArray intCodeInterceptedResult;
	private static PrintWriter writer;
	private static UnixSocketChannel channel;
	private static Integer VMPID;
	private static final String applicationUUID;

	static {

		applicationUUID = UUID.randomUUID().toString();
		PATTERN = Pattern.compile(IAgentConstants.TRACE_REGEX);
		methodMap = new HashSet<String>(Arrays.asList(IAgentConstants.COMPLETE_LIST));
		allClasses = new HashSet<String>(Arrays.asList(IAgentConstants.ALL_CLASSES));
		executorMathods = new HashSet<String>(Arrays.asList(IAgentConstants.EXECUTORS));
		interceptMethod = new HashMap<String, List<String>>();
		for (int i = 0; i < IAgentConstants.ALL_METHODS.length; i++) {
			interceptMethod.put(IAgentConstants.ALL_CLASSES[i], new ArrayList<String>(Arrays.asList(IAgentConstants.ALL_METHODS[i])));
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
				//To support docker older versions
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

	@Override
	public void init(String arg) throws Exception {
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
		intCodeInterceptedResult = new JSONArray();
	}

	private String getCmdLineArgsByProc(Integer pid) {
		File cmdlineFile = new File("/proc/"+pid+"/cmdline");
		if (!cmdlineFile.isFile())
			return null;
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(cmdlineFile));
			String cmdline = br.readLine();
			if(!cmdline.isEmpty())
				return cmdline;
		} catch (IOException e) {
		}
		finally {
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

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	protected synchronized void doOnStart(Object source, Object[] arg, String executionId) {
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

		if (sourceString != null && methodMap.contains(sourceString)) {
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
			if (executorMathods.contains(sourceString)) {
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
					intCodeResultBean.setUserAPIInfo(trace[traceId].getLineNumber(), klassName, trace[traceId].getMethodName());
					intCodeResultBean.setParameters(toString(arg));
					if (traceId > 0)
						intCodeResultBean.setCurrentMethod(trace[traceId - 1].getMethodName());
					generateEvent(intCodeResultBean);
				} else
					intCodeInterceptedResult.clear();
			} else
				intCodeInterceptedResult.add(intCodeResultBean);

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

	@SuppressWarnings("unchecked")
	private void generateEvent(IntCodeResultBean intCodeResultBean) {
		// trace(logFile, intCodeInterceptedResult.toString());
		System.out.println("publish event: "+intCodeResultBean);
		if(!channel.isConnected()) {
			System.out.println("try re connect");
			if (!rootFile.exists()) {
				throw new RuntimeException("Root doesn't exists, Please start the K2-IntCode Agent");
			}
			try {
				UnixSocketAddress address = new UnixSocketAddress(this.rootFile);
				channel.connect(address);
				writer = new PrintWriter(Channels.newOutputStream(channel));
				System.out.println("K2 UDSServer Connection restablished!!!");
			}
			catch (IOException e) {
				throw new RuntimeException(e.getMessage());
			}
		}
		intCodeResultBean.setEventGenerationTime(System.currentTimeMillis());
		intCodeInterceptedResult.add(intCodeResultBean);
		writer.println(intCodeInterceptedResult.toString());
		writer.flush();
		intCodeInterceptedResult.clear();
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
		if (source instanceof Method) {
			m = (Method) source;
			sourceString = m.toGenericString();
		}

		if (IAgentConstants.MSSQL_EXECUTOR.equals(sourceString)) {
			String klassName;
			StackTraceElement[] trace = Thread.currentThread().getStackTrace();
			IntCodeResultBean intCodeResultBean = (IntCodeResultBean) intCodeInterceptedResult.get(0);
			for (int i = 0; i < trace.length; i++) {
				klassName = trace[i].getClassName();
				if (!PATTERN.matcher(klassName).matches()) {
					intCodeResultBean.setUserAPIInfo(trace[i].getLineNumber(), klassName, trace[i].getMethodName());
					if (i > 0)
						intCodeResultBean.setCurrentMethod(trace[i - 1].getMethodName());
					break;
				}
			}
			intCodeInterceptedResult.remove(0);
			generateEvent(intCodeResultBean);
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

	private static String getParameterValue(Object obj) {
		try {
			Field f = obj.getClass().getDeclaredField("setterDTV");
			f.setAccessible(true);
			Object objx = f.get(obj);
			if (objx.getClass().getName().contains("DTV")) {
				Field f2 = objx.getClass().getDeclaredField("impl");
				f2.setAccessible(true);
				Object objA = f2.get(objx);
				if (objA.getClass().getName().contains("AppDTVImpl")) {
					f = objA.getClass().getDeclaredField("value");
					f.setAccessible(true);
					return JsonCodec.getInstance().transform(f.get(objA).toString());
				}
			}
		} catch (Exception e) {
		}
		return null;
	}

	@SuppressWarnings({ "unchecked", "unused" })
	private static JSONArray toString(Object[] obj) {
		if (obj == null) {
			return null;
		}
		JSONArray parameters = new JSONArray();

		// StringBuilder b = new StringBuilder();
		// b.append('[');
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
				try {
					if (obj[i].getClass().getName().equals("com.microsoft.sqlserver.jdbc.Parameter")) {
						JSONObject objx = new JSONObject();
						parameters.add(getParameterValue(obj[i]));
						// b.append(getParameterValue(obj[i]));
					} else {
						parameters.add(JsonCodec.getInstance().transform(obj[i]));
						// b.append(JsonCodec.getInstance().transform(obj[i]));
					}
				} catch (Throwable th) {
					parameters.add((obj[i] != null) ? JsonCodec.getInstance().transform(obj[i].toString()) : null);
				}
			// if (i != obj.length - 1)
			// b.append(',');
		}
		// b.append(']');
		// return b.toString();
		return parameters;
	}

}