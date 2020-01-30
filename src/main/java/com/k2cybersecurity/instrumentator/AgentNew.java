package com.k2cybersecurity.instrumentator;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.matcher.ElementMatchers;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;

import static com.k2cybersecurity.instrumentator.utils.InstrumentationUtils.doInstrument;
import static com.k2cybersecurity.instrumentator.utils.InstrumentationUtils.setIAST;

/**
 * Hello world!
 */
public class AgentNew {

	private static boolean isDynamicAttachment = false;

	public static void premain(String arguments, Instrumentation instrumentation) {
//		AgentBuilder agentBuilder = new AgentBuilder.Default().ignore(ElementMatchers.none())
//				.with(AgentBuilder.Listener.StreamWriting.toSystemError())
//				.with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
////				.with(AgentBuilder.TypeStrategy.Default.REBASE)
//				.with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE);

		try {
			Class<?> clazz = Class.forName("com.k2cybersecurity.instrumentator.K2Instrumentator");
			Method init = clazz.getMethod("init", Boolean.class);
			init.invoke(null, isDynamicAttachment);
		} catch (Exception e) {
//			e.printStackTrace();
		}
		
		AgentBuilder agentBuilder = new AgentBuilder.Default()
				.ignore(ElementMatchers.nameStartsWith("sun.reflect.com.k2cybersecurity")).disableClassFormatChanges()
//				.with(AgentBuilder.Listener.StreamWriting.toSystemError())
				.with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
//				.with(new AgentBuilder.CircularityLock.Global())
//				.with(AgentBuilder.TypeStrategy.Default.REDEFINE)
//				.with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
		;
		
		if(StringUtils.equals("IAST", arguments)) {
			setIAST(true);
		}
		
		agentBuilder = doInstrument(agentBuilder, Hooks.TYPE_BASED_HOOKS, "TYPE_BASED");
		agentBuilder = doInstrument(agentBuilder, Hooks.NAME_BASED_HOOKS, "NAME_BASED");

		agentBuilder.installOn(instrumentation);
		
	}

	public static void agentmain(String agentArgs, Instrumentation instrumentation)
			throws InstantiationException, IOException {
		isDynamicAttachment = true;
		premain(agentArgs, instrumentation);
	}
}
