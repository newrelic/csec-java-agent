package java.lang;

import com.newrelic.api.agent.weaver.SkipIfPresent;

@SkipIfPresent(originalName = "java.lang.ProcessHandle")
public interface ProcessHandle_Instrumentation{
}