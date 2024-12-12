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
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.FileOperation;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;

@Weave(type = MatchType.ExactClass, originalName = "java.io.RandomAccessFile")
public abstract class RandomAccessFile_Instrumentation {

    private void open(String name, int mode) throws FileNotFoundException {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(name);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if(isFileLockAcquired){
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
    }

    private static boolean acquireFileLockIfPossible(VulnerabilityCaseType fileOperation) {
        return GenericHelper.acquireLockIfPossible(fileOperation, FileHelper.getNrSecCustomAttribName());
    }

    private static void releaseFileLock() {
        GenericHelper.releaseLock(FileHelper.getNrSecCustomAttribName());
    }

    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation == null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            FileHelper.checkEntryOfFileIntegrity(((FileOperation)operation).getFileName());
            NewRelicSecurity.getAgent().registerOperation(operation);
        } catch (Throwable ignored){
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, ignored.getMessage()), ignored, RandomAccessFile_Instrumentation.class.getName());
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
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, e.getMessage()), e, RandomAccessFile_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, e.getMessage()), e, RandomAccessFile_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, e.getMessage()), e, RandomAccessFile_Instrumentation.class.getName());        
        }
        return null;
    }
}
