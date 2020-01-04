package com.k2cybersecurity.instrumentator;

import static com.k2cybersecurity.instrumentator.utils.InstrumentationUtils.doInstrument;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.matcher.ElementMatchers;

/**
 * Hello world!
 */
public class AgentNew {

	public static void premain(String arguments, Instrumentation instrumentation) {
		AgentBuilder agentBuilder = new AgentBuilder.Default().ignore(ElementMatchers.none())
				.with(AgentBuilder.Listener.StreamWriting.toSystemError())
				.with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
//				.with(AgentBuilder.TypeStrategy.Default.REBASE)
				.with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE);

		agentBuilder = doInstrument(agentBuilder, Hooks.TYPE_BASED_HOOKS, "TYPE_BASED");
		agentBuilder = doInstrument(agentBuilder, Hooks.NAME_BASED_HOOKS, "NAME_BASED");
		agentBuilder.installOn(instrumentation);
		try {
			Class<?> clazz = Class.forName("com.k2cybersecurity.instrumentator.K2Instrumentator");
			Method init = clazz.getMethod("init", null);
			init.invoke(null, null);
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchMethodException e) {
			e.printStackTrace();
		} catch (SecurityException e) {
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		} catch (InvocationTargetException e) {
			e.printStackTrace();
		}
	}

	public static void agentmain(String agentArgs, Instrumentation instrumentation)
			throws InstantiationException, IOException {
		premain(agentArgs, instrumentation);
	}
}
