package com.k2cybersecurity.instrumentator.custom;

import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.utility.JavaModule;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

public class ClassLoadListener implements AgentBuilder.Listener {


    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String TRANSFORMATION_ERROR_CLASS_S_ERROR_LAZY = "[INSTRUMENTATION][LAZY] Error while instrumenting class : %s";
    public static final String TRANSFORMED_CLASS_S_LAZY = "[INSTRUMENTATION][LAZY] Instrumented %s";
    public static String TRANSFORMATION_ERROR_CLASS_S_ERROR = "[INSTRUMENTATION] Error while instrumenting class : %s";
    public static String TRANSFORMED_CLASS_S = "[INSTRUMENTATION] Instrumented %s";
    public static final String IGNORED_CLASS_S = "Ignored : class : %s";
    public static final String COMPLETED_CLASS_S = "Completed : class : %s";
    public static final String DISCOVERED_CLASS_S = "Discovered : class : %s";
    public static final String JAVA_LANG_ARRAY_STORE_EXCEPTION = "java.lang.ArrayStoreException:";

    @Override
    public void onError(
            final String typeName,
            final ClassLoader classLoader,
            final JavaModule module,
            final boolean loaded,
            final Throwable throwable) {
//		System.out.println(String.format("Transformation error : class : %s :: error %s", typeName,
//				Arrays.asList(throwable.getStackTrace())));
        if (!StringUtils.contains(throwable.toString(), JAVA_LANG_ARRAY_STORE_EXCEPTION)) {
            logger.logInit(LogLevel.ERROR, String.format(TRANSFORMATION_ERROR_CLASS_S_ERROR, typeName), throwable, ClassLoadListener.class.getName());
        }

    }

    @Override
    public void onTransformation(
            final TypeDescription typeDescription,
            final ClassLoader classLoader,
            final JavaModule module,
            final boolean loaded,
            final DynamicType dynamicType) {
        AgentUtils.getInstance().getTransformedClasses().add(Pair.of(typeDescription.getName(), classLoader));
        AgentUtils.getInstance().createProtectedVulnerabilties(typeDescription, classLoader);
//		System.out.println("Transformed class : " + typeDescription.getName());
        logger.logInit(LogLevel.INFO, String.format(TRANSFORMED_CLASS_S, typeDescription.getName()), ClassLoadListener.class.getName());
    }

    @Override
    public void onIgnored(
            final TypeDescription typeDescription,
            final ClassLoader classLoader,
            final JavaModule module,
            final boolean loaded) {
//		logger.log(LogLevel.DEBUG, String.format(IGNORED_CLASS_S, typeDescription.getName()), ClassLoadListener.class.getName());

        //      log.debug("onIgnored {}", typeDescription.getName());
    }

    @Override
    public void onComplete(
            final String typeName,
            final ClassLoader classLoader,
            final JavaModule module,
            final boolean loaded) {
        //      log.debug("onComplete {}", typeName);
        try {
            ThreadLocalTransformationLock.getInstance().release(typeName);

            AgentUtils.getInstance().putClassloaderRecord(typeName, classLoader);
//			logger.log(LogLevel.DEBUG, String.format(COMPLETED_CLASS_S, typeName), ClassLoadListener.class.getName());
        } catch (Throwable e) {
//			System.out.println("Error while registering classloader : " + typeName + " : " + classLoader + " : " + e.getMessage() + " : " + e.getCause());
        }
        AgentUtils.getInstance().addProtectedVulnerabilties(typeName);
    }

    @Override
    public void onDiscovery(
            final String typeName,
            final ClassLoader classLoader,
            final JavaModule module,
            final boolean loaded) {
        ThreadLocalTransformationLock.getInstance().acquire(typeName);
//		logger.log(LogLevel.DEBUG, String.format(DISCOVERED_CLASS_S, typeName), ClassLoadListener.class.getName());

        //      log.debug("onDiscovery {}", typeName);
//		System.out.println("Discovered class : " + typeName);

    }
}