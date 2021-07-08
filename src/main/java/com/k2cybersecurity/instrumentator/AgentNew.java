package com.k2cybersecurity.instrumentator;

import com.k2cybersecurity.instrumentator.custom.ClassLoadListener;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.InstrumentationUtils;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.dynamic.scaffold.TypeValidation;
import net.bytebuddy.matcher.ElementMatchers;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.SystemUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

import static com.k2cybersecurity.instrumentator.utils.InstrumentationUtils.*;


public class AgentNew {

	private static boolean isDynamicAttachment = false;

	private static boolean initDone = false;

	public static Instrumentation gobalInstrumentation;

	public static void premain(String arguments, Instrumentation instrumentation) {
		if (StringUtils.equals(System.getenv().get("K2_DISABLE"), "true") || StringUtils.equals(System.getenv().get("K2_ATTACH"), "false")) {
			System.err.println("[K2-JA] Process attachment aborted!!! K2 is set to disable.");
			return;
		}

		System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "off");
		System.setProperty("org.slf4j.simpleLogger.logFile", "System.out");

		if (initDone) {
			return;
		}
		initDone = true;
		gobalInstrumentation = instrumentation;

		try {
			Class<?> clazz = Class.forName("com.k2cybersecurity.instrumentator.K2Instrumentator");
			Method init = clazz.getMethod("init", Boolean.class);
			Boolean isStarted = (Boolean) init.invoke(null, isDynamicAttachment);
			if (!isStarted) {
				System.err.println("[K2-JA] Process initialization failed!!! Environment incompatible.");
				return;
			}
			Runtime.getRuntime().addShutdownHook(new Thread(() -> InstrumentationUtils.shutdownLogic(false)));

			Set<Class> typeBasedClassSet = new HashSet<>();
			for (Class aClass : instrumentation.getAllLoadedClasses()) {
				if (Hooks.NAME_BASED_HOOKS.containsKey(aClass.getName())) {
					AgentUtils.getInstance().getTransformedClasses().add(Pair.of(aClass.getName(), aClass.getClassLoader()));
				} else if (Hooks.TYPE_BASED_HOOKS.containsKey(aClass.getName())) {
					typeBasedClassSet.add(aClass);
				}
			}

			/**
			 * IMPORTANT : Don't touch this shit until & unless very very necessary.
			 */
			AgentBuilder agentBuilder = new AgentBuilder.Default(new ByteBuddy().with(TypeValidation.DISABLED))
					.ignore(ElementMatchers.nameStartsWith("sun.reflect.com.k2cybersecurity"))
					.disableClassFormatChanges()
//									.with(AgentBuilder.Listener.StreamWriting.toSystemOut())
					.with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION).with(new ClassLoadListener()).with(AgentBuilder.TypeStrategy.Default.REDEFINE)
//					.with(AgentBuilder.CircularityLock.Inactive.INSTANCE)
//					.with(new AgentBuilder.CircularityLock.Global())
//					.with(AgentBuilder.LambdaInstrumentationStrategy.ENABLED)
					;

			if (StringUtils.equals("IAST", arguments)) {
				setIAST(true);
			}

			agentBuilder = doInstrument(agentBuilder, Hooks.TYPE_BASED_HOOKS, "TYPE_BASED", Hooks.DECORATOR_ENTRY);
			agentBuilder = doInstrument(agentBuilder, Hooks.NAME_BASED_HOOKS, "NAME_BASED", Hooks.DECORATOR_ENTRY);
			agentBuilder = doInstrument(agentBuilder, Hooks.ANNOTATION_BASED_HOOKS, Hooks.DECORATOR_ENTRY);

			if (getIAST()) {
				agentBuilder = doInstrument(agentBuilder, IASTHooks.TYPE_BASED_HOOKS, "TYPE_BASED", IASTHooks.DECORATOR_ENTRY);
				agentBuilder = doInstrument(agentBuilder, IASTHooks.NAME_BASED_HOOKS, "NAME_BASED", IASTHooks.DECORATOR_ENTRY);
				agentBuilder = doInstrument(agentBuilder, IASTHooks.ANNOTATION_BASED_HOOKS, IASTHooks.DECORATOR_ENTRY);

			}


			resettableClassFileTransformer = agentBuilder.installOn(instrumentation);

			// Checks for type based classes to hook
			for (Class aClass : instrumentation.getAllLoadedClasses()) {
				if (instrumentation.isModifiableClass(aClass)) {
					for (Class typeClass : typeBasedClassSet) {
						if (typeClass.isAssignableFrom(aClass) && !AgentUtils.getInstance().getTransformedClasses()
								.contains(Pair.of(aClass.getName(), aClass.getClassLoader()))) {
							AgentUtils.getInstance().getTransformedClasses().add(Pair.of(aClass.getName(), aClass.getClassLoader()));
							break;
						}
					}
				}
			}
			retransformHookedClasses(instrumentation);
		} catch (Throwable e) {
            String tmpDir = System.getProperty("java.io.tmpdir");
			System.err.println("[K2-JA] Process initialization failed!!! Please find the error in " + tmpDir + File.separator + "K2-Instrumentation.err");
			try {
                e.printStackTrace(new PrintStream(tmpDir + File.separator + "K2-Instrumentation.err"));
			} catch (FileNotFoundException ex) {
			}
		}
	}

	public static void agentmain(String agentArgs, Instrumentation instrumentation) {
		isDynamicAttachment = true;
		if (!StringUtils.equals(System.getenv().get("K2_DYNAMIC_ATTACH"), "true")) {
			System.err.println("[K2-JA] Process attachment aborted!!! collector's dynamic attachment not allowed.");
			return;
		}
		premain(agentArgs, instrumentation);
	}

}
