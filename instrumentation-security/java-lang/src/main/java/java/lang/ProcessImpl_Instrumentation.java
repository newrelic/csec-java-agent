package java.lang;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.ForkExecOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.io.IOException;
import java.util.Map;

@Weave(type = MatchType.ExactClass, originalName = "java.lang.ProcessImpl")
abstract class ProcessImpl_Instrumentation {

    static Process start(String[] cmdarray,
                         java.util.Map<String,String> environment,
                         String dir,
                         ProcessBuilder.Redirect[] redirects,
                         boolean redirectErrorStream) throws IOException {
        Process p = null;
        String executionId = preprocessSecurityHook(cmdarray, environment);
        try {
            p = Weaver.callOriginal();
        } finally {
            registerExitOperation(executionId, VulnerabilityCaseType.SYSTEM_COMMAND);
        }
        return p;
    }

    private static void registerExitOperation(String executionId, VulnerabilityCaseType type) {
        try {
            NewRelicSecurity.getAgent().registerExitEvent(executionId, type);
        } catch (Throwable ignored){}
    }

    private static String preprocessSecurityHook(String[] cmdarray, Map<String, String> environment) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
                || cmdarray == null || cmdarray.length == 0
            ) {
                return null;
            }
            String command = String.join(" ", cmdarray);
            ForkExecOperation operation = new ForkExecOperation(command, environment,
                    ProcessImpl_Instrumentation.class.getName(), "start");
            return NewRelicSecurity.getAgent().registerOperation(operation);

        } catch (Throwable e) {
            if(e instanceof NewRelicSecurityException){
                e.printStackTrace();
                throw e;
            }
        }
        return null;
    }
}
