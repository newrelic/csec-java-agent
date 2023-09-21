package com.newrelic.agent.security.instrumentation.javaio.lang;

import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;

@Weave(type = MatchType.Interface, originalName = "java.lang.ProcessHandle")
public abstract class ProcessHandle_Instrumentation {
}