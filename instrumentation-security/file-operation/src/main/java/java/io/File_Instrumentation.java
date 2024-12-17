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

import java.util.ArrayList;
import java.util.List;

@Weave(type = MatchType.BaseClass, originalName = "java.io.File")
public abstract class File_Instrumentation {

    public boolean createNewFile() throws IOException {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_CREATE_NEW_FILE, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    public boolean delete() {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_DELETE, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    public void deleteOnExit() {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_DELETE_ON_EXIT, false, this);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
    }

    public String[] list() {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_LIST, false, this);
        }
        String[] returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    public String[] list(FilenameFilter filter) {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_LIST, false, this);
        }
        String[] returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    public File[] listFiles() {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_LISTFILES, false, this);
        }
        File[] returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    public File[] listFiles(FilenameFilter filter) {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_LISTFILES, false, this);
        }
        File[] returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    public File[] listFiles(FileFilter filter) {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_LISTFILES, false, this);
        }
        File[] returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    public boolean mkdir() {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_MKDIR, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    public boolean mkdirs() {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_MKDIRS, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    public boolean renameTo(File_Instrumentation dest) {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_RENAME_TO, false, this, dest);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    public boolean setReadOnly() {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_SET_READ_ONLY, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    public boolean setWritable(boolean writable, boolean ownerOnly) {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_SET_WRITABLE, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    public boolean setWritable(boolean writable) {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_SET_WRITABLE, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    public boolean setReadable(boolean readable, boolean ownerOnly) {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_SET_READABLE, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    public boolean setReadable(boolean readable) {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_SET_READABLE, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    public boolean setExecutable(boolean executable, boolean ownerOnly) {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_SET_EXECUTABLE, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    public boolean setExecutable(boolean executable) {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_SET_EXECUTABLE, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                registerExitOperation(isFileLockAcquired, operation);
                releaseFileLock();
            }
        }
        return returnVal;
    }

    // TODO: static createTempFile methods are not hooked since we don't have a way to protect against them.

    public abstract String getName();

    public abstract String getAbsolutePath();

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
            NewRelicSecurity.getAgent().registerOperation(operation);
        } catch (Throwable ignored) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, ignored.getMessage()), ignored, File_Instrumentation.class.getName());
        }
    }

    private static AbstractOperation preprocessSecurityHook(boolean isBooleanAttributesCall, String methodName, boolean isLowSeverityHook,
            File_Instrumentation... files) {
        try {
            if (files == null || files.length == 0
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
            return operation;
        } catch (Throwable e) {
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, e.getMessage()), e, File_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, e.getMessage()), e, File_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, e.getMessage()), e, File_Instrumentation.class.getName());
        }
        return null;
    }
}
