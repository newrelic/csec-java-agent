package com.k2cybersecurity.intcodeagent.utils.instrumentation;

import com.k2cybersecurity.intcodeagent.Agent;
import com.k2cybersecurity.intcodeagent.Hooks;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.utility.JavaModule;

import java.util.List;
import java.util.Map;

import static net.bytebuddy.matcher.ElementMatchers.*;

public class InstrumentationUtils {
    public static AgentBuilder doInstrument(AgentBuilder builder, Map<String, List<String>> hookMap, String typeOfHook) {
        for (Map.Entry<String, List<String>> entry : hookMap.entrySet()) {
            String sourceClass = entry.getKey();
            List<String> methods = entry.getValue();
            for (String method : methods) {
                System.out.println(String.format("Came to instrument : %s::%s", sourceClass, method));
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

                builder = junction
                        .transform(new AgentBuilder.Transformer() {
                            @Override
                            public DynamicType.Builder<?> transform(DynamicType.Builder<?> builder, TypeDescription typeDescription, ClassLoader classLoader, JavaModule javaModule) {

                                try {
                                    if (Agent.hookedAPIs.contains(typeDescription.getName() + "." + method)){
                                        return builder;
                                    }
                                    System.out.println(String.format("Instrumenting : %s::%s for key : %s : %s", sourceClass, method, (sourceClass + "." + method),  typeDescription.getName()));
                                    Class methodEntryDecorator = Class.forName(Hooks.DECORATOR_ENTRY.get(sourceClass + "." + method) + "." + "MethodEntry");
                                    Class methodExitDecorator = Class.forName(Hooks.DECORATOR_ENTRY.get(sourceClass + "." + method) + "." + "MethodExit");
                                    Class methodVoidExitDecorator = Class.forName(Hooks.DECORATOR_ENTRY.get(sourceClass + "." + method) + "." + "MethodVoidExit");

                                    Class staticMethodEntryDecorator = Class.forName(Hooks.DECORATOR_ENTRY.get(sourceClass + "." + method) + "." + "StaticMethodEntry");
                                    Class staticMethodExitDecorator = Class.forName(Hooks.DECORATOR_ENTRY.get(sourceClass + "." + method) + "." + "StaticMethodExit");
                                    Class staticMethodVoidExitDecorator = Class.forName(Hooks.DECORATOR_ENTRY.get(sourceClass + "." + method) + "." + "StaticMethodVoidExit");

                                    Class constructorExitDecorator = Class.forName(Hooks.DECORATOR_ENTRY.get(sourceClass + "." + method) + "." + "ConstructorExit");
                                    Agent.hookedAPIs.add(typeDescription.getName() + "." + method);
                                    if (method == null) {
                                        return builder.visit(Advice.to(staticMethodEntryDecorator, constructorExitDecorator)
                                                .on(isConstructor()));
                                    }
                                    return builder
                                            .visit(Advice.to(methodEntryDecorator, methodExitDecorator)
                                                    .on(not(isStatic()).and(not(isConstructor()).and(not(returns(TypeDescription.VOID))).and(hasMethodName(method)))))
                                            .visit(Advice.to(methodEntryDecorator, methodVoidExitDecorator)
                                                    .on(not(isStatic()).and(not(isConstructor()).and(returns(TypeDescription.VOID)).and(hasMethodName(method)))))
                                            .visit(Advice.to(staticMethodEntryDecorator, staticMethodExitDecorator)
                                                    .on(isStatic().and(not(isConstructor()).and(not(returns(TypeDescription.VOID))).and(hasMethodName(method)))))
                                            .visit(Advice.to(staticMethodEntryDecorator, staticMethodVoidExitDecorator)
                                                    .on(isStatic().and(not(isConstructor())).and(returns(TypeDescription.VOID)).and(hasMethodName(method))));
                                } catch (ClassNotFoundException e) {
                                    System.err.println(String.format("Failed to instrument : %s::%s due to error : %s", sourceClass, method, e));
                                    e.printStackTrace();
                                }
                                return builder;
                            }
                        });
            }
        }
        return builder;
    }

}
