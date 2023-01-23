package nr.java.lang;

import com.newrelic.api.agent.weaver.Weave;

@Weave(originalName = "java.lang.ProcessHandle")
public interface ProcessHandle_Instrumentation {
}