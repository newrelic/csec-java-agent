package com.k2cybersecurity.instrumentator.utils;

import com.k2cybersecurity.instrumentator.AgentNew;
import com.k2cybersecurity.instrumentator.Hooks;
import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.custom.ByteBuddyElementMatchers;
import com.k2cybersecurity.instrumentator.dispatcher.DispatcherPool;
import com.k2cybersecurity.intcodeagent.controlcommand.ControlCommandProcessorThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.EventThreadPool;
import com.k2cybersecurity.intcodeagent.logging.HealthCheckScheduleThread;
import com.k2cybersecurity.intcodeagent.logging.ServletEventPool;
import com.k2cybersecurity.intcodeagent.models.javaagent.ShutDownEvent;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;
import com.k2cybersecurity.intcodeagent.websocket.WSClient;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.agent.builder.ResettableClassFileTransformer;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.utility.JavaModule;
import org.apache.commons.lang3.tuple.Pair;

import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static net.bytebuddy.matcher.ElementMatchers.*;

public class InstrumentationUtils {

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String NAME_BASED = "NAME_BASED";
    public static final String TYPE_BASED = "TYPE_BASED";
    public static final String METHOD_ENTRY = "MethodEntry";
    public static final String METHOD_EXIT = "MethodExit";
    public static final String METHOD_VOID_EXIT = "MethodVoidExit";
    public static final String STATIC_METHOD_ENTRY = "StaticMethodEntry";
    public static final String STATIC_METHOD_EXIT = "StaticMethodExit";
    public static final String CONSTRUCTOR_EXIT = "ConstructorExit";
    public static final String CONSTRUCTOR_ENTRY = "ConstructorEntry";
    public static final String STATIC_METHOD_VOID_EXIT = "StaticMethodVoidExit";
    public static final String FAILED_TO_INSTRUMENT_S_S_DUE_TO_ERROR_S = "Failed to instrument : %s::%s due to error : %s";
    public static final String FAILED_TO_INSTRUMENT_ANNOTATION_DUE_TO_ERROR = "Failed to instrument : %s due to error : %s";

    public static final String TERMINATING = "Terminating";
    public static final String SHUTTING_DOWN_WITH_STATUS = "Shutting down with status: ";
    public static final String JAVA_AGENT_SHUTDOWN_COMPLETE = "Java Agent shutdown complete.";
    public static final String ORG_JBOSS_MODULES_MAIN = "org.jboss.modules.Main";
    public static final String ORG_OSGI_FRAMEWORK_BUNDLE = "org.osgi.framework.Bundle";
    public static final String DOT = ".";
    public static final String DECORATORS = "Decorators";
    public static final String $ = "$";

    private static Boolean IAST = false;

    public static ResettableClassFileTransformer resettableClassFileTransformer;

    public static AgentBuilder doInstrument(AgentBuilder builder, Map<String, List<String>> hookMap,
                                            String typeOfHook) {
        for (Map.Entry<String, List<String>> entry : hookMap.entrySet()) {
            String sourceClass = entry.getKey();
            List<String> methods = entry.getValue();
            if (!IAST && Hooks.IAST_BASED_HOOKS.contains(entry.getKey())) {
                continue;
            }
            for (String method : methods) {
                AgentBuilder.Identified.Narrowable junction = builder.type(not(isInterface()));
                switch (typeOfHook) {
                    case NAME_BASED:
                        junction = junction.and(named(sourceClass));
                        break;
                    case TYPE_BASED:
                        junction = junction.and(ByteBuddyElementMatchers.safeHasSuperType(named(sourceClass)));
                        //                    junction = junction.and(hasSuperType(named(sourceClass)));
                        break;
                    default:
                        break;
                }
                builder = junction.transform(new AgentBuilder.Transformer() {
                    @Override
                    public DynamicType.Builder<?> transform(DynamicType.Builder<?> builder,
                                                            TypeDescription typeDescription, ClassLoader classLoader, JavaModule javaModule) {
                        try {

                            //							System.out.println(String.format("Instrumenting : %s::%s for key : %s : %s", sourceClass,
                            //									method, (sourceClass + "." + method), typeDescription.getName()));
                            Class methodEntryDecorator = Class
                                    .forName(Hooks.DECORATOR_ENTRY.get(sourceClass + DOT + method) + DOT + DECORATORS
                                                    + $ + METHOD_ENTRY,
                                            true, classLoader);

                            Class methodExitDecorator = Class
                                    .forName(Hooks.DECORATOR_ENTRY.get(sourceClass + DOT + method) + DOT + DECORATORS
                                                    + $ + METHOD_EXIT,
                                            true, classLoader);
                            Class methodVoidExitDecorator = Class.forName(
                                    Hooks.DECORATOR_ENTRY.get(sourceClass + DOT + method) + DOT + DECORATORS + $ + METHOD_VOID_EXIT,
                                    true, classLoader);

                            Class staticMethodEntryDecorator = Class.forName(
                                    Hooks.DECORATOR_ENTRY.get(sourceClass + DOT + method) + DOT + DECORATORS + $ + STATIC_METHOD_ENTRY,
                                    true, classLoader);

                            Class staticMethodExitDecorator = Class.forName(
                                    Hooks.DECORATOR_ENTRY.get(sourceClass + DOT + method) + DOT + DECORATORS + $ + STATIC_METHOD_EXIT,
                                    true, classLoader);

                            Class staticMethodVoidExitDecorator = Class.forName(
                                    Hooks.DECORATOR_ENTRY.get(sourceClass + DOT + method) + DOT + DECORATORS + $
                                            + STATIC_METHOD_VOID_EXIT, true, classLoader);

                            Class constructorEntryDecorator = Class.forName(
                                    Hooks.DECORATOR_ENTRY.get(sourceClass + DOT + method) + DOT + DECORATORS + $ + CONSTRUCTOR_ENTRY,
                                    true, classLoader);

                            Class constructorExitDecorator = Class.forName(
                                    Hooks.DECORATOR_ENTRY.get(sourceClass + DOT + method) + DOT + DECORATORS + $ + CONSTRUCTOR_EXIT,
                                    true, classLoader);
                            if (method == null) {
                                return builder.visit(Advice.to(constructorEntryDecorator, constructorExitDecorator,
                                        new K2ClassLocater(constructorEntryDecorator.getClassLoader()))
                                        .on(isConstructor()));
                            }
                            return builder
                                    .visit(Advice.to(methodEntryDecorator, methodExitDecorator,
                                            new K2ClassLocater(methodEntryDecorator.getClassLoader())).on(not(isStatic())
                                            .and(not(isConstructor()).and(not(returns(TypeDescription.VOID)))
                                                    .and(hasMethodName(method)))))
                                    .visit(Advice
                                            .to(methodEntryDecorator, methodVoidExitDecorator,
                                                    new K2ClassLocater(methodEntryDecorator.getClassLoader()))
                                            .on(not(isStatic()).and(not(isConstructor()).and(returns(TypeDescription.VOID))
                                                    .and(hasMethodName(method)))))
                                    .visit(Advice
                                            .to(staticMethodEntryDecorator, staticMethodExitDecorator,
                                                    new K2ClassLocater(methodEntryDecorator.getClassLoader())).on(isStatic()
                                                    .and(not(isConstructor()).and(not(returns(TypeDescription.VOID)))
                                                            .and(hasMethodName(method)))))
                                    .visit(Advice
                                            .to(staticMethodEntryDecorator, staticMethodVoidExitDecorator,
                                                    new K2ClassLocater(methodEntryDecorator.getClassLoader()))
                                            .on(isStatic().and(not(isConstructor())).and(returns(TypeDescription.VOID))
                                                    .and(hasMethodName(method))));
                        } catch (ClassNotFoundException e) {
                            logger.log(LogLevel.ERROR,
                                    String.format(FAILED_TO_INSTRUMENT_S_S_DUE_TO_ERROR_S, sourceClass, method, e), e,
                                    InstrumentationUtils.class.getName());
                        }
                        return builder;
                    }
                });
            }
        }
        return builder;
    }


    public static AgentBuilder doInstrument(AgentBuilder builder, Set<String> hooks,
                                            String typeOfHook) {
        for (String entry : hooks) {
            AgentBuilder.Identified.Narrowable junction = builder.type(not(isInterface()));

            junction = junction.and(isAnnotatedWith(named(entry)));

            builder = junction.transform(new AgentBuilder.Transformer() {
                @Override
                public DynamicType.Builder<?> transform(DynamicType.Builder<?> builder,
                                                        TypeDescription typeDescription, ClassLoader classLoader, JavaModule javaModule) {
                    try {

                        //							System.out.println(String.format("Instrumenting : %s::%s for key : %s : %s", sourceClass,
                        //									method, (sourceClass + "." + method), typeDescription.getName()));
                        Class methodEntryDecorator = Class
                                .forName(Hooks.DECORATOR_ENTRY.get(entry) + DOT + DECORATORS
                                                + $ + METHOD_ENTRY,
                                        true, classLoader);

                        Class methodExitDecorator = Class
                                .forName(Hooks.DECORATOR_ENTRY.get(entry) + DOT + DECORATORS
                                                + $ + METHOD_EXIT,
                                        true, classLoader);
                        Class methodVoidExitDecorator = Class.forName(
                                Hooks.DECORATOR_ENTRY.get(entry) + DOT + DECORATORS + $ + METHOD_VOID_EXIT,
                                true, classLoader);

                        Class staticMethodEntryDecorator = Class.forName(
                                Hooks.DECORATOR_ENTRY.get(entry) + DOT + DECORATORS + $ + STATIC_METHOD_ENTRY,
                                true, classLoader);

                        Class staticMethodExitDecorator = Class.forName(
                                Hooks.DECORATOR_ENTRY.get(entry) + DOT + DECORATORS + $ + STATIC_METHOD_EXIT,
                                true, classLoader);

                        Class staticMethodVoidExitDecorator = Class.forName(
                                Hooks.DECORATOR_ENTRY.get(entry) + DOT + DECORATORS + $
                                        + STATIC_METHOD_VOID_EXIT, true, classLoader);

                        return builder
                                .visit(Advice.to(methodEntryDecorator, methodExitDecorator,
                                        new K2ClassLocater(methodEntryDecorator.getClassLoader())).on(not(isStatic())
                                        .and(not(isConstructor()).and(not(returns(TypeDescription.VOID)))
                                                .and(isMethod()))))
                                .visit(Advice
                                        .to(methodEntryDecorator, methodVoidExitDecorator,
                                                new K2ClassLocater(methodEntryDecorator.getClassLoader()))
                                        .on(not(isStatic()).and(not(isConstructor()).and(returns(TypeDescription.VOID))
                                                .and(isMethod()))))
                                .visit(Advice
                                        .to(staticMethodEntryDecorator, staticMethodExitDecorator,
                                                new K2ClassLocater(methodEntryDecorator.getClassLoader())).on(isStatic()
                                                .and(not(isConstructor()).and(not(returns(TypeDescription.VOID)))
                                                        .and(isMethod()))))
                                .visit(Advice
                                        .to(staticMethodEntryDecorator, staticMethodVoidExitDecorator,
                                                new K2ClassLocater(methodEntryDecorator.getClassLoader()))
                                        .on(isStatic().and(not(isConstructor())).and(returns(TypeDescription.VOID))
                                                .and(isMethod())));
                    } catch (ClassNotFoundException e) {
                        logger.log(LogLevel.ERROR,
                                String.format(FAILED_TO_INSTRUMENT_S_S_DUE_TO_ERROR_S, entry, e), e,
                                InstrumentationUtils.class.getName());
                    }
                    return builder;
                }
            });
        }
        return builder;
    }


    public static void shutdownLogic(boolean doResetInstrumentation) {
//        System.out.println("K2 Collector's shutdown hooked called.");
        try {
            ShutDownEvent shutDownEvent = new ShutDownEvent();
            shutDownEvent.setApplicationUUID(K2Instrumentator.APPLICATION_UUID);
            shutDownEvent.setStatus(TERMINATING);
            EventSendPool.getInstance().sendEvent(shutDownEvent.toString());
            logger.log(LogLevel.INFO, SHUTTING_DOWN_WITH_STATUS + shutDownEvent, InstrumentationUtils.class.getName());
            TimeUnit.SECONDS.sleep(1);
        } catch (Throwable e) {
            logger.log(LogLevel.SEVERE, "Error while sending shut down event : ", e,
                    InstrumentationUtils.class.getName());
        }
        try {
            WSClient.getInstance().close();
        } catch (Throwable e) {
        }
        try {
            ServletEventPool.getInstance().shutDownThreadPoolExecutor();
            HealthCheckScheduleThread.getInstance().shutDownThreadPoolExecutor();
            EventThreadPool.getInstance().shutDownThreadPoolExecutor();
            DispatcherPool.getInstance().shutDownThreadPoolExecutor();
            ControlCommandProcessorThreadPool.getInstance().shutDownThreadPoolExecutor();
            EventSendPool.getInstance().shutDownThreadPoolExecutor();
        } catch (Throwable e) {
            logger.log(LogLevel.SEVERE, "Error while shutting down K2 Pools : ", e,
                    InstrumentationUtils.class.getName());
        }

        try {
            if (doResetInstrumentation) {
                logger.log(LogLevel.INFO, "K2 instrumentation reset result : " + resettableClassFileTransformer
                                .reset(AgentNew.gobalInstrumentation, AgentBuilder.RedefinitionStrategy.RETRANSFORMATION),
                        InstrumentationUtils.class.getName());
            }

            retransformHookedClasses(AgentNew.gobalInstrumentation);
        } catch (Throwable e) {
            logger.log(LogLevel.SEVERE, "Error while resetting K2 instrumentation : ", e,
                    InstrumentationUtils.class.getName());
        }
        logger.log(LogLevel.SEVERE, JAVA_AGENT_SHUTDOWN_COMPLETE, InstrumentationUtils.class.getName());
    }

    public static Boolean getIAST() {
        return IAST;
    }

    public static void setIAST(Boolean iAST) {
        IAST = iAST;
    }

    public static void retransformHookedClasses(Instrumentation instrumentation) {
        for (Pair<String, ClassLoader> pair : new ArrayList<>(AgentUtils.getInstance().getTransformedClasses())) {
            try {
                Class klass = Class.forName(pair.getLeft(), false, pair.getRight());
                instrumentation.retransformClasses(klass);
            } catch (Throwable e) {
                logger.log(LogLevel.SEVERE, "Error while retransformHookedClasses : ", e,
                        InstrumentationUtils.class.getName());
            }
        }
    }

}
