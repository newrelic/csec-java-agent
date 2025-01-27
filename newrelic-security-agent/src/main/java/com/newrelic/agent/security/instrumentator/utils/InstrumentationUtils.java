package com.newrelic.agent.security.instrumentator.utils;

import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.instrumentator.dispatcher.DispatcherPool;
import com.newrelic.agent.security.instrumentator.os.OsVariablesInstance;
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
    public static final String JAVA_AGENT_SHUTDOWN_COMPLETE = "Java Agent shutdown complete.";

    private static Boolean IAST = false;

    public static void shutdownLogic() {
        try {
            AgentInfo.getInstance().setAgentActive(false);
            ShutDownEvent shutDownEvent = new ShutDownEvent();
            shutDownEvent.setApplicationUUID(AgentInfo.getInstance().getApplicationUUID());
            shutDownEvent.setStatus(IAgentConstants.TERMINATING);
            EventSendPool.getInstance().sendEvent(shutDownEvent);
            logger.log(LogLevel.INFO, IAgentConstants.SHUTTING_DOWN_WITH_STATUS + shutDownEvent, InstrumentationUtils.class.getName());
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
