/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package java.io;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.instrumentation.helpers.FileHelper;
import com.newrelic.api.agent.security.instrumentation.helpers.GenericHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.FileOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.ExactClass, originalName = "java.io.FileInputStream")
public abstract class FileInputStream_Instrumentation {

    private void open(String name) throws FileNotFoundException {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(name);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isFileLockAcquired){
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
    }

    private boolean acquireFileLockIfPossible() {
        try {
            return FileHelper.acquireFileLockIfPossible();
        } catch (Throwable ignored) {}
        return false;
    }

    private void releaseFileLock() {
        try {
            FileHelper.releaseFileLock();
        } catch (Throwable e) {}
    }

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            FileHelper.checkEntryOfFileIntegrity(((FileOperation)operation).getFileName());
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, ignored.getMessage()), ignored, FileInputStream_Instrumentation.class.getName());
        }
    }

    private AbstractOperation preprocessSecurityHook(String filename) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
                    || filename == null || filename.trim().isEmpty()
            ) {
                return null;
            }
            String filePath = new File(filename).getAbsolutePath();
            FileOperation operation = new FileOperation(filePath,
                    this.getClass().getName(), FileHelper.METHOD_NAME_FILEOUTPUTSTREAM_OPEN);
            FileHelper.createEntryOfFileIntegrity(filePath, this.getClass().getName(), FileHelper.METHOD_NAME_FILEOUTPUTSTREAM_OPEN);
            NewRelicSecurity.getAgent().registerOperation(operation);
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, e.getMessage()), e, FileInputStream_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, e.getMessage()), e, FileInputStream_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, e.getMessage()), e, FileInputStream_Instrumentation.class.getName());
        }
        return null;
    }
}
