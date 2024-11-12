package com.newrelic.agent.security.instrumentation.random.java.io;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.FileHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.FileOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.util.ArrayList;
import java.util.List;

@Weave(type = MatchType.BaseClass, originalName = "java.io.File")
public abstract class File_Instrumentation {
    public abstract String getName();

    public abstract String getAbsolutePath();

    public boolean exists() {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        boolean isOwaspHookEnabled = NewRelicSecurity.getAgent().isLowPriorityInstrumentationEnabled();

        AbstractOperation operation = null;
        if (isOwaspHookEnabled && isFileLockAcquired && !FileHelper.skipExitEvent(this.getName()) && LowSeverityHelper.isOwaspHookProcessingNeeded()) {
            operation = preprocessSecurityHook(true, FileHelper.METHOD_NAME_EXISTS, true, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isOwaspHookEnabled) {
                registerExitOperation(isFileLockAcquired, operation);
            }
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        return returnVal;
    }

    private static boolean acquireFileLockIfPossible(VulnerabilityCaseType fileOperation) {
        return GenericHelper.acquireLockIfPossible(fileOperation, FileHelper.getNrSecCustomAttribName());
    }

    private static void releaseFileLock() {
        GenericHelper.releaseLock(FileHelper.getNrSecCustomAttribName());
    }


    private static void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            FileHelper.checkEntryOfFileIntegrity(((FileOperation)operation).getFileName());
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable e) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE,
                    LowSeverityHelper.LOW_PRIORITY_INSTRUMENTATION, e.getMessage()), e, File_Instrumentation.class.getName());
        }
    }

    private static AbstractOperation preprocessSecurityHook(boolean isBooleanAttributesCall, String methodName, boolean isLowSeverityHook,
                                                            File_Instrumentation... files) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
                    || files == null || files.length == 0
            ) {
                return null;
            }
            List<String> fileNames = new ArrayList<>(files.length);
            for (File_Instrumentation file : files) {
                String filePath = file.getAbsolutePath();
                fileNames.add(filePath);
                FileHelper.createEntryOfFileIntegrity(file.getAbsolutePath(), File_Instrumentation.class.getName(), methodName);
            }
            FileOperation operation = new FileOperation(
                    File_Instrumentation.class.getName(), methodName, isBooleanAttributesCall, fileNames);
            if(isBooleanAttributesCall) {
                operation.setLowSeverityHook(isLowSeverityHook);
            }
            NewRelicSecurity.getAgent().registerOperation(operation);
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, LowSeverityHelper.LOW_PRIORITY_INSTRUMENTATION, e.getMessage()), e, File_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LowSeverityHelper.LOW_PRIORITY_INSTRUMENTATION, e.getMessage()), e, File_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, LowSeverityHelper.LOW_PRIORITY_INSTRUMENTATION, e.getMessage()), e, File_Instrumentation.class.getName());
        }
        return null;
    }
}