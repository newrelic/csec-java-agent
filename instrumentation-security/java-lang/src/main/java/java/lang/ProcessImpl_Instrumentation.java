package java.lang;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.ForkExecOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
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
        AbstractOperation operation = preprocessSecurityHook(cmdarray, environment);
        p = Weaver.callOriginal();
        registerExitOperation(operation);
        return p;
    }

    private static void registerExitOperation(AbstractOperation operation) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, "JAVA-LANG", ignored.getMessage()), ignored, ProcessImpl_Instrumentation.class.getName());
        }
    }

    private static AbstractOperation preprocessSecurityHook(String[] cmdarray, Map<String, String> environment) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
                || cmdarray == null || cmdarray.length == 0
            ) {
                return null;
            }
            String command = String.join(" ", cmdarray);
            ForkExecOperation operation = new ForkExecOperation(command, environment,
                    ProcessImpl_Instrumentation.class.getName(), "start");
            NewRelicSecurity.getAgent().registerOperation(operation);
            return operation;
        } catch (Throwable e) {
            if(e instanceof NewRelicSecurityException){
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, "JAVA-LANG", e.getMessage()), e, ProcessImpl_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, "JAVA-LANG", e.getMessage()), e, ProcessImpl_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, "JAVA-LANG", e.getMessage()), e, ProcessImpl_Instrumentation.class.getName());
        }
        return null;
    }
}
