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
import java.util.concurrent.TimeUnit;

import static com.k2cybersecurity.instrumentator.utils.InstrumentationUtils.*;


public class AgentNew {

	private static boolean isDynamicAttachment = false;

	public static Instrumentation gobalInstrumentation;

	public static void premain(String arguments, Instrumentation instrumentation) {
		if (StringUtils.equals(System.getenv().get("K2_DISABLE"), "true") || StringUtils.equals(System.getenv().get("K2_ATTACH"), "false")) {
			System.err.println("[K2-JA] Process attachment aborted!!! K2 is set to disable.");
			return;
		}
        if (StringUtils.isBlank(System.getenv("K2_GROUP_NAME"))) {
            System.err.println("[K2-JA] Process attachment aborted!!! K2_GROUP_NAME is not set.");
            return;
        }

		System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "off");
		System.setProperty("org.slf4j.simpleLogger.logFile", "System.out");

		gobalInstrumentation = instrumentation;


		Thread k2JaStartupThread = new Thread("K2-JA-StartUp") {
			@Override
			public void run() {
				try {
					awaitServerStartUp(instrumentation, ClassLoader.getSystemClassLoader());

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
		};
		k2JaStartupThread.setDaemon(true);
		k2JaStartupThread.start();

	}

	public static void agentmain(String agentArgs, Instrumentation instrumentation) {
		isDynamicAttachment = true;
		if (!StringUtils.equals(System.getenv().get("K2_DYNAMIC_ATTACH"), "true")) {
			System.err.println("[K2-JA] Process attachment aborted!!! collector's dynamic attachment not allowed.");
			return;
		}
		premain(agentArgs, instrumentation);
	}

	public static void awaitServerStartUp(Instrumentation instrumentation, ClassLoader classLoader) {
		System.out.println("[K2-JA] trying server detection .");
		if (jbossDetected(classLoader, instrumentation)) {
			// Place Classloader adjustments
//            ClassloaderAdjustments.jbossSpecificAdjustments();
			System.out.println("[K2-JA] JBoss detected server wait initialised.");
			awaitJbossServerStartInitialization(instrumentation);
		}
	}

	private static boolean jbossDetected(ClassLoader classLoader, Instrumentation instrumentation) {
		if (classLoader.getResource("org/jboss/modules/Main.class") != null) {
			return true;
		}
		if (isClassLoaded("org.jboss.modules.Main", instrumentation)) {
			return true;
		}
		return false;
	}

	private static void awaitJbossServerStartInitialization(Instrumentation instrumentation) {
		//wait max 5 mins
		long interval = 1000;

		long waitTime = TimeUnit.MINUTES.toMillis(5);
		int itr = 0;
		while (itr * interval < waitTime) {
			String loggingManagerClassName = System.getProperty("java.util.logging.manager");
			if (StringUtils.isBlank(loggingManagerClassName)) {
				continue;
			}
			System.out.println("[K2-JA] log manager detected : " + loggingManagerClassName);
			if (isClassLoaded(loggingManagerClassName, instrumentation)) {
				return;
			}
		}

	}

	protected static boolean isClassLoaded(String className, Instrumentation instrumentation) {
		if (instrumentation == null || className == null) {
			throw new IllegalArgumentException("instrumentation and className must not be null");
		}
		Class<?>[] classes = instrumentation.getAllLoadedClasses();
		if (classes != null) {
			for (Class<?> klass : classes) {
//            System.out.println("[K2-JA] loaded classes : " + klass.getName());
				if (className.equals(klass.getName())) {
					return true;
				}
			}
		}
		return false;
	}

}
