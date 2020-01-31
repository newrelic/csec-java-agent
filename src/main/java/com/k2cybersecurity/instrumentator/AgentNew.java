package com.k2cybersecurity.instrumentator;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.matcher.ElementMatchers;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

import static com.k2cybersecurity.instrumentator.utils.InstrumentationUtils.doInstrument;
import static com.k2cybersecurity.instrumentator.utils.InstrumentationUtils.setIAST;

/**
 * Hello world!
 */
public class AgentNew {

    private static boolean isDynamicAttachment = false;

    private static boolean initDone = false;

    public static void premain(String arguments, Instrumentation instrumentation) {
        if (initDone) {
            return;
        }
//		AgentBuilder agentBuilder = new AgentBuilder.Default().ignore(ElementMatchers.none())
//				.with(AgentBuilder.Listener.StreamWriting.toSystemError())
//				.with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
////				.with(AgentBuilder.TypeStrategy.Default.REBASE)
//				.with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE);
        Set<Class> typeBasedClassSet = new HashSet<Class>();
        Set<Class> classesToBeReloaded = new HashSet<>();
        if (isDynamicAttachment) {
            for (Class aClass : instrumentation.getAllLoadedClasses()) {
                if (Hooks.NAME_BASED_HOOKS.containsKey(aClass.getName())) {
                    classesToBeReloaded.add(aClass);
                } else if (Hooks.TYPE_BASED_HOOKS.containsKey(aClass.getName())) {
                    typeBasedClassSet.add(aClass);
                }
            }
        }

        try {
            Class<?> clazz = Class.forName("com.k2cybersecurity.instrumentator.K2Instrumentator");
            Method init = clazz.getMethod("init", Boolean.class);
            init.invoke(null, isDynamicAttachment);
        } catch (Exception e) {
//			e.printStackTrace();
        }

        /**
         * IMPORTANT : Don't touch this shit until & unless very very necessary.
         */
        AgentBuilder agentBuilder = new AgentBuilder.Default()
                .ignore(ElementMatchers.nameStartsWith("sun.reflect.com.k2cybersecurity")).disableClassFormatChanges()
                .with(AgentBuilder.Listener.StreamWriting.toSystemOut())
                .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
//				.with(AgentBuilder.TypeStrategy.Default.REDEFINE)

                ;

        if (StringUtils.equals("IAST", arguments)) {
            setIAST(true);
        }

        agentBuilder = doInstrument(agentBuilder, Hooks.TYPE_BASED_HOOKS, "TYPE_BASED");
        agentBuilder = doInstrument(agentBuilder, Hooks.NAME_BASED_HOOKS, "NAME_BASED");

        agentBuilder.installOn(instrumentation);

        if (isDynamicAttachment) {
            // Checks for type based classes to hook
            for (Class aClass : instrumentation.getAllLoadedClasses()) {
                if (instrumentation.isModifiableClass(aClass)) {
                    typeBasedClassSet.forEach((typeClass -> {
                        if (typeClass.isAssignableFrom(aClass)) {
                            classesToBeReloaded.add(aClass);
                        }
                    }));
                }
            }
            try {
                if (classesToBeReloaded.size() > 0) {
                    System.out.println("Classes to be retransformed are : " + classesToBeReloaded);
                    instrumentation.retransformClasses(classesToBeReloaded.toArray(new Class[0]));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        initDone = true;
    }

    public static void agentmain(String agentArgs, Instrumentation instrumentation)
            throws InstantiationException, IOException {
        isDynamicAttachment = true;
        premain(agentArgs, instrumentation);
    }
}
