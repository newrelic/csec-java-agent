package com.k2cybersecurity.instrumentator.utils;

import static net.bytebuddy.matcher.ElementMatchers.hasMethodName;
import static net.bytebuddy.matcher.ElementMatchers.hasSuperType;
import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.isInterface;
import static net.bytebuddy.matcher.ElementMatchers.isStatic;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.not;
import static net.bytebuddy.matcher.ElementMatchers.returns;

import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.k2cybersecurity.instrumentator.Hooks;
import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.IPScheduledThread;
import com.k2cybersecurity.intcodeagent.logging.ServletEventPool;
import com.k2cybersecurity.intcodeagent.models.javaagent.ShutDownEvent;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.k2cybersecurity.intcodeagent.websocket.WSClient;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.utility.JavaModule;

public class InstrumentationUtils {
	
	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
	
	public static AgentBuilder doInstrument(AgentBuilder builder, Map<String, List<String>> hookMap,
			String typeOfHook) {
		for (Map.Entry<String, List<String>> entry : hookMap.entrySet()) {
			String sourceClass = entry.getKey();
			List<String> methods = entry.getValue();
			for (String method : methods) {
				AgentBuilder.Identified.Narrowable junction = builder.type(not(isInterface()));
				switch (typeOfHook) {
				case "NAME_BASED":
					junction = junction.and(named(sourceClass));
					break;
				case "TYPE_BASED":
					junction = junction.and(hasSuperType(named(sourceClass)));
					break;
				default:
					break;
				}
				System.out.println(String.format("Came to instrument : %s::%s :: %s", sourceClass, method, typeOfHook));
				builder = junction.transform(new AgentBuilder.Transformer() {
					@Override
					public DynamicType.Builder<?> transform(DynamicType.Builder<?> builder,
							TypeDescription typeDescription, ClassLoader classLoader, JavaModule javaModule) {
						try {

							if (K2Instrumentator.hookedAPIs.contains(typeDescription.getName() + "." + method)) {
								return builder;
							}
							System.out.println(String.format("Instrumenting : %s::%s for key : %s : %s", sourceClass,
									method, (sourceClass + "." + method), typeDescription.getName()));
							Class methodEntryDecorator = Class.forName(
									Hooks.DECORATOR_ENTRY.get(sourceClass + "." + method) + "." + "MethodEntry");
							Class methodExitDecorator = Class.forName(
									Hooks.DECORATOR_ENTRY.get(sourceClass + "." + method) + "." + "MethodExit");
							Class methodVoidExitDecorator = Class.forName(
									Hooks.DECORATOR_ENTRY.get(sourceClass + "." + method) + "." + "MethodVoidExit");

							Class staticMethodEntryDecorator = Class.forName(
									Hooks.DECORATOR_ENTRY.get(sourceClass + "." + method) + "." + "StaticMethodEntry");
							Class staticMethodExitDecorator = Class.forName(
									Hooks.DECORATOR_ENTRY.get(sourceClass + "." + method) + "." + "StaticMethodExit");
							Class staticMethodVoidExitDecorator = Class
									.forName(Hooks.DECORATOR_ENTRY.get(sourceClass + "." + method) + "."
											+ "StaticMethodVoidExit");

							Class constructorExitDecorator = Class.forName(
									Hooks.DECORATOR_ENTRY.get(sourceClass + "." + method) + "." + "ConstructorExit");
							K2Instrumentator.hookedAPIs.add(typeDescription.getName() + "." + method);
							if (method == null) {
								return builder.visit(Advice.to(staticMethodEntryDecorator, constructorExitDecorator)
										.on(isConstructor()));
							}
							return builder.visit(Advice.to(methodEntryDecorator, methodExitDecorator)
									.on(not(isStatic()).and(not(isConstructor()).and(not(returns(TypeDescription.VOID)))
											.and(hasMethodName(method)))))
									.visit(Advice.to(methodEntryDecorator, methodVoidExitDecorator)
											.on(not(isStatic()).and(not(isConstructor())
													.and(returns(TypeDescription.VOID)).and(hasMethodName(method)))))
									.visit(Advice.to(staticMethodEntryDecorator, staticMethodExitDecorator).on(
											isStatic().and(not(isConstructor()).and(not(returns(TypeDescription.VOID)))
													.and(hasMethodName(method)))))
									.visit(Advice.to(staticMethodEntryDecorator, staticMethodVoidExitDecorator)
											.on(isStatic().and(not(isConstructor())).and(returns(TypeDescription.VOID))
													.and(hasMethodName(method))));
						} catch (ClassNotFoundException e) {
							System.err.println(String.format("Failed to instrument : %s::%s due to error : %s",
									sourceClass, method, e));
							e.printStackTrace();
						}
						return builder;
					}
				});
			}
		}
		return builder;
	}

	public static void shutdownLogic() {
		ShutDownEvent shutDownEvent = new ShutDownEvent();
		shutDownEvent.setApplicationUUID(K2Instrumentator.APPLICATION_UUID);
		shutDownEvent.setStatus("Terminating");
		EventSendPool.getInstance().sendEvent(shutDownEvent.toString());
		logger.log(LogLevel.INFO, "Shutting down with status: " + shutDownEvent, InstrumentationUtils.class.getName());
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

//		Agent.globalInstr.removeTransformer(classTransformer);
		logger.log(LogLevel.SEVERE, "Java Agent shutdown complete.", InstrumentationUtils.class.getName());
	}

}
