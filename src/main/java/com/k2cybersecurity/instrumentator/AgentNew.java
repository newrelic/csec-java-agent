package com.k2cybersecurity.instrumentator;

import net.bytebuddy.agent.builder.AgentBuilder;

import java.lang.instrument.Instrumentation;
import java.util.HashSet;
import java.util.Set;

import static com.k2cybersecurity.instrumentator.utils.InstrumentationUtils.doInstrument;

/**
 * Hello world!
 */
public class AgentNew {

    public static Set<String> hookedAPIs = new HashSet<>();

    public static void premain(String arguments, Instrumentation instrumentation) {
        AgentBuilder agentBuilder = new AgentBuilder.Default()
                .with(AgentBuilder.Listener.StreamWriting.toSystemError())
                .with(AgentBuilder.TypeStrategy.Default.REBASE)
                .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION);

        agentBuilder = doInstrument(agentBuilder, Hooks.TYPE_BASED_HOOKS, "TYPE_BASED");
        agentBuilder = doInstrument(agentBuilder, Hooks.NAME_BASED_HOOKS, "NAME_BASED");
        agentBuilder.installOn(instrumentation);
    }
}

