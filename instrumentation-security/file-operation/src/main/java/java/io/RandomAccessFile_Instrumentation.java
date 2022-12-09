/*
 *
 *  * Copyright 2020 New Relic Corporation. All rights reserved.
 *  * SPDX-License-Identifier: Apache-2.0
 *
 */

package java.io;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.exceptions.NewRelicSecurityException;
import com.newrelic.api.agent.security.schema.operation.FileOperation;
import com.newrelic.api.agent.weaver.MatchType;
import com.newrelic.api.agent.weaver.Weave;
import com.newrelic.api.agent.weaver.Weaver;
import com.nr.instrumentation.security.javaio.FileHelper;

@Weave(type = MatchType.ExactClass, originalName = "java.io.RandomAccessFile")
public abstract class RandomAccessFile_Instrumentation {

    private void open(String name, int mode) throws FileNotFoundException {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if(isFileLockAcquired && !FileHelper.skipExistsEvent(name)) {
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
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored){}
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
                    FileOutputStream_Instrumentation.class.getName(), FileHelper.METHOD_NAME_FILEOUTPUTSTREAM_OPEN, false);
            FileHelper.createEntryOfFileIntegrity(filePath, FileOutputStream_Instrumentation.class.getName(), FileHelper.METHOD_NAME_FILEOUTPUTSTREAM_OPEN);
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
