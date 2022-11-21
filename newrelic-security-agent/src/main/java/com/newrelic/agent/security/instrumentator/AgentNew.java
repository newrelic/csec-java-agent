package com.newrelic.agent.security.instrumentator;

import com.newrelic.agent.security.instrumentator.utils.AgentUtils;
import com.newrelic.agent.security.instrumentator.utils.InstrumentationUtils;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.LogLevel;
import com.newrelic.api.agent.NewRelic;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;


public class AgentNew {

    private static final String HOOKS_ADDED_SUCCESSFULLY = "[STEP-6][COMPLETE][INSTRUMENTATION] Instrumentation applied.";
    private static final String CONTINUED_TRANSFORMATION_MSG = "[INSTRUMENTATION] Dynamic security hooks will be placed as the classes are loaded.";
    private static final String INSTRUMENT_WILL_INSTRUMENT_CLASS = "[INSTRUMENTATION] Will modify class %s";
    private static final String STARTED_ADDING_HOOKS = "[STEP-6][BEGIN][INSTRUMENTATION] Applying instrumentation";

    private static boolean isDynamicAttachment = false;

    public static Instrumentation gobalInstrumentation;

    public static final String K2_BOOTSTAP_LOADED_PACKAGE_NAME = "sun.reflect.com.k2cybersecurity";

    private static boolean initDone = false;


    /**
     * This is called via the Java 1.5 Instrumentation startup. init of the agent.
     * Will add required transformer to underline JVM.
     **/
    public static void premain(String arguments, Instrumentation instrumentation) {
        if (initDone) {
            return;
        }
        initDone = true;

        /* K2_DISABLE is no longer valid */
        if (StringUtils.equals(System.getenv().get("K2_DISABLE"), "true") || NewRelic.getAgent().getConfig().getValue("security.force_complete_disable", false)) {
            System.err.println("[K2-JA] Process attachment aborted!!! K2 is set to disable.");
            NewRelic.getAgent().getLogger().log(Level.INFO, "Security disabled forcefully!!! To enable security please set config parameter security.force_complete_disable or env K2_DISABLE to false and restart the application.");
            return;
        }

        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "off");
        System.setProperty("org.slf4j.simpleLogger.logFile", "System.out");

        gobalInstrumentation = instrumentation;

        // Setting K2_HOME
        if (!K2Instrumentator.setK2HomePath()) {
            return;
        }

        /*
            Check if agent is running in standalone mode.
         */
        if (StringUtils.equals(NewRelic.getAgent().getClass().getSimpleName(), "NoOpAgent")) {
            AgentUtils.getInstance().setStandaloneMode(true);
            AgentUtils.getInstance().setAgentActive(true);
        } else {
            AgentUtils.getInstance().setAgentActive(false);
        }
        Thread k2JaStartupThread = new Thread("K2-Security-StartUp") {
            @Override
            public void run() {
                try {
                    awaitServerStartUp(instrumentation, ClassLoader.getSystemClassLoader());
                    FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

                    Class<?> clazz = Class.forName("com.newrelic.agent.security.instrumentator.K2Instrumentator");
                    Method init = clazz.getMethod("init", Boolean.class);
                    Boolean isStarted = (Boolean) init.invoke(null, isDynamicAttachment);
                    if (!isStarted) {
                        System.err.println("[K2-JA] Process initialization failed!!! Environment incompatible.");
                        return;
                    }
                    logger.logInit(LogLevel.INFO, STARTED_ADDING_HOOKS, AgentNew.class.getName());
                    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                        InstrumentationUtils.shutdownLogic(false);
                    }, "k2-shutdown-hook"));

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
        try {
            System.out.println("[K2-JA] trying server detection .");
            if (jbossDetected(classLoader, instrumentation)) {
                // Place Classloader adjustments
                jbossSpecificAdjustments();
                System.out.println("[K2-JA] JBoss detected server wait initialised.");
                awaitJbossServerStartInitialization(instrumentation);
            }
        } catch (Throwable t) {
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

    public static void jbossSpecificAdjustments() {
        String cur = System.getProperty("jboss.modules.system.pkgs");
        if (StringUtils.isBlank(cur)) {
            System.setProperty("jboss.modules.system.pkgs", K2_BOOTSTAP_LOADED_PACKAGE_NAME);
        } else if (!StringUtils.containsIgnoreCase(cur, K2_BOOTSTAP_LOADED_PACKAGE_NAME)) {
            System.setProperty("jboss.modules.system.pkgs", StringUtils.joinWith(",", cur, K2_BOOTSTAP_LOADED_PACKAGE_NAME));
        }
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
            try {
                TimeUnit.MILLISECONDS.sleep(interval);
            } catch (InterruptedException e) {
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
