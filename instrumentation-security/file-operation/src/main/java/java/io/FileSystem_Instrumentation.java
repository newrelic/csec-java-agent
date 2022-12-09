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

@Weave(type = MatchType.BaseClass, originalName = "java.io.FileSystem")
abstract class FileSystem_Instrumentation {

    public int getBooleanAttributes(File f){
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if(isFileLockAcquired && !FileHelper.skipExistsEvent(f.getName())) {
            operation = preprocessSecurityHook(f, true, FileHelper.METHOD_NAME_GET_BOOLEAN_ATTRIBUTES);
        }
        int returnVal = -1;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isFileLockAcquired){
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public boolean setPermission(File f, int access, boolean enable, boolean owneronly){
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if(isFileLockAcquired && !FileHelper.skipExistsEvent(f.getName())) {
            operation = preprocessSecurityHook(f, false, FileHelper.METHOD_NAME_SET_PERMISSION);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isFileLockAcquired){
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public boolean createFileExclusively(String pathname)
            throws IOException {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if(isFileLockAcquired && !FileHelper.skipExistsEvent(pathname)) {
            operation = preprocessSecurityHook(new File(pathname), false, FileHelper.METHOD_NAME_CREATE_FILE_EXCLUSIVELY);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isFileLockAcquired){
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public boolean delete(File f){
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if(isFileLockAcquired && !FileHelper.skipExistsEvent(f.getName())) {
            operation = preprocessSecurityHook(f, false, FileHelper.METHOD_NAME_DELETE);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isFileLockAcquired){
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public String[] list(File f){
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if(isFileLockAcquired && !FileHelper.skipExistsEvent(f.getName())) {
            operation = preprocessSecurityHook(f, false, FileHelper.METHOD_NAME_LIST);
        }
        String[] returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isFileLockAcquired){
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }


    public boolean createDirectory(File f){
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if(isFileLockAcquired && !FileHelper.skipExistsEvent(f.getName())) {
            operation = preprocessSecurityHook(f, false, FileHelper.METHOD_NAME_CREATE_DIRECTORY);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isFileLockAcquired){
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public boolean rename(File f1, File f2){
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if(isFileLockAcquired && !FileHelper.skipExistsEvent(f1.getName())) {
            operation = preprocessSecurityHook(f1, false, FileHelper.METHOD_NAME_RENAME);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isFileLockAcquired){
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public boolean setReadOnly(File f){
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if(isFileLockAcquired && !FileHelper.skipExistsEvent(f.getName())) {
            operation = preprocessSecurityHook(f, false, FileHelper.METHOD_NAME_SETREADONLY);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if(isFileLockAcquired){
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
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
        } catch (Throwable ignored) {}
    }


    private void registerExitOperation(boolean isProcessingAllowed, AbstractOperation operation) {
        try {
            if (operation!= null || !isProcessingAllowed || !NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            NewRelicSecurity.getAgent().registerExitEvent(operation);
        } catch (Throwable ignored){}
    }

    private AbstractOperation preprocessSecurityHook(File file, boolean isBooleanAttributesCall, String methodName) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
                    || file == null
            ) {
                return null;
            }
            String filePath = file.getAbsolutePath();
            FileOperation operation = new FileOperation(filePath,
                    FileOutputStream_Instrumentation.class.getName(), methodName, isBooleanAttributesCall);
            FileHelper.createEntryOfFileIntegrity(filePath, FileSystem_Instrumentation.class.getName(), methodName);
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
