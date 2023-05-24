package com.nr.agent.security.random.java.io;

import com.newrelic.api.agent.NewRelic;
import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.FileHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.FileOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

import java.util.ArrayList;
import java.util.List;

import static com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper.DEFAULT;
import static com.newrelic.api.agent.security.instrumentation.helpers.LowSeverityHelper.LOW_SEVERITY_HOOKS_ENABLED;

@Weave(type = MatchType.BaseClass, originalName = "java.io.File")
public abstract class File_Instrumentation {
    public abstract String getName();

    public abstract String getAbsolutePath();

    public boolean exists() {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        boolean isOwaspHookEnabled = NewRelic.getAgent().getConfig().getValue(LOW_SEVERITY_HOOKS_ENABLED, DEFAULT);

        AbstractOperation operation = null;
        if (isOwaspHookEnabled && isFileLockAcquired && !FileHelper.skipExistsEvent(this.getName()) && LowSeverityHelper.isOwaspHookProcessingNeeded()) {
            operation = preprocessSecurityHook(true, FileHelper.METHOD_NAME_EXISTS, true, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            registerExitOperation(isFileLockAcquired, operation);
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        return returnVal;
    }

    private static boolean acquireFileLockIfPossible() {
        try {
            return FileHelper.acquireFileLockIfPossible();
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static void releaseFileLock() {
        try {
            FileHelper.releaseFileLock();
        } catch (Throwable ignored) {
        }
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
        } catch (Throwable ignored) {
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
                FileHelper.createEntryOfFileIntegrity(file.getAbsolutePath(), File_Instrumentation.class.getName(),
                        methodName, FileOperation.EXISTS_OP);
            }
            FileOperation operation = new FileOperation(
                    File_Instrumentation.class.getName(), methodName, isBooleanAttributesCall, FileOperation.EXISTS_OP, fileNames);
            if(isBooleanAttributesCall) {
                operation.setLowSeverityHook(isLowSeverityHook);
            }
            NewRelicSecurity.getAgent().registerOperation(operation);
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                e.printStackTrace();
                throw e;
            }
        }
        return null;
    }
}