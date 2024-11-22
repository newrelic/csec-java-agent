package com.newrelic.agent.security.instrumentator.utils;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.dispatcher.DispatcherPool;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
import com.newrelic.agent.security.intcodeagent.communication.ConnectionFactory;
import com.newrelic.agent.security.intcodeagent.controlcommand.ControlCommandProcessorThreadPool;
import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.agent.security.intcodeagent.schedulers.FileCleaner;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.agent.security.intcodeagent.logging.HealthCheckScheduleThread;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import com.newrelic.agent.security.intcodeagent.models.javaagent.ShutDownEvent;
import com.newrelic.agent.security.intcodeagent.websocket.EventSendPool;
import com.newrelic.agent.security.intcodeagent.websocket.WSClient;
import com.newrelic.agent.security.intcodeagent.websocket.WSReconnectionST;
import org.apache.commons.io.FileUtils;
import org.java_websocket.framing.CloseFrame;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.util.concurrent.TimeUnit;

/**
 * Instrumentation related Utilities
 */
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
    public static final String JAVA_AGENT_SHUTDOWN_COMPLETE = "Java Agent shutdown complete.";
    public static final String ORG_JBOSS_MODULES_MAIN = "org.jboss.modules.Main";
    public static final String ORG_OSGI_FRAMEWORK_BUNDLE = "org.osgi.framework.Bundle";
    public static final String DOT = ".";
    public static final String DECORATORS = "Decorators";
    public static final String $ = "$";
    private static final String INSTRUMENTATION_TRANSFORM_ERROR = "[INSTRUMENTATION] Couldn't transform class `%s`: ";
    private static final String INSTRUMENTATION_RETRANSFORM_STARTED = "[INSTRUMENTATION] Started static re-transformation of classes.";
    private static final String INSTRUMENTATION_RETRANSFORM_ENDED = "[INSTRUMENTATION] Finished static re-transformation of classes.";

    private static Boolean IAST = false;

    public static void shutdownLogic() {
//        System.out.println("K2 Collector's shutdown hooked called.");
//        AgentUtils.getInstance().setAgentActive(false);
        try {
            AgentInfo.getInstance().setAgentActive(false);
            ShutDownEvent shutDownEvent = new ShutDownEvent();
            shutDownEvent.setApplicationUUID(AgentInfo.getInstance().getApplicationUUID());
            shutDownEvent.setStatus(IAgentConstants.TERMINATING);
            EventSendPool.getInstance().sendEvent(shutDownEvent, "postShutDown");
            logger.log(LogLevel.INFO, IAgentConstants.SHUTTING_DOWN_WITH_STATUS + shutDownEvent, InstrumentationUtils.class.getName());
            TimeUnit.SECONDS.sleep(1);
        } catch (Throwable e) {
            logger.log(LogLevel.SEVERE, "Error while sending shut down event : ", e,
                    InstrumentationUtils.class.getName());
        }
        try {
            ConnectionFactory.getInstance().getSecurityConnection().close("IAST agent shutting down");
        } catch (Throwable e) {
        }
        try {
            HealthCheckScheduleThread.getInstance().cancelTask(true);
            DispatcherPool.shutDownPool();
            ControlCommandProcessorThreadPool.shutDownPool();
            EventSendPool.shutDownPool();
            WSReconnectionST.shutDownPool();
            WSClient.shutDownWSClient(true, CloseFrame.NORMAL, "IAST agent shutting down");
            FileCleaner.cancelTask();
            if(StringUtils.isNotBlank(OsVariablesInstance.getInstance().getOsVariables().getTmpDirectory())) {
                FileUtils.deleteQuietly(new File(OsVariablesInstance.getInstance().getOsVariables().getTmpDirectory()));
            }

        } catch (Throwable e) {
            logger.log(LogLevel.SEVERE, "Error while shutting down executor pools : ", e,
                    InstrumentationUtils.class.getName());
        }
        logger.log(LogLevel.SEVERE, JAVA_AGENT_SHUTDOWN_COMPLETE, InstrumentationUtils.class.getName());
        try {
            FileLoggerThreadPool.getInstance().shutDownThreadPoolExecutor();
        } catch (Exception e) {
        }
    }

    public static Boolean getIAST() {
        return IAST;
    }

    public static void setIAST(Boolean iAST) {
        IAST = iAST;
    }

}
