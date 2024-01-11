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

import java.util.ArrayList;
import java.util.List;

@Weave(type = MatchType.BaseClass, originalName = "java.io.File")
public abstract class File_Instrumentation {

    public boolean createNewFile() throws IOException {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_CREATE_NEW_FILE, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public boolean delete() {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_DELETE, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public void deleteOnExit() {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_DELETE_ON_EXIT, false, this);
        }
        try {
            Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
    }

    public String[] list() {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_LIST, false, this);
        }
        String[] returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public String[] list(FilenameFilter filter) {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_LIST, false, this);
        }
        String[] returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public File[] listFiles() {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_LISTFILES, false, this);
        }
        File[] returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public File[] listFiles(FilenameFilter filter) {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_LISTFILES, false, this);
        }
        File[] returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public File[] listFiles(FileFilter filter) {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_LISTFILES, false, this);
        }
        File[] returnVal = null;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public boolean mkdir() {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_MKDIR, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public boolean mkdirs() {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_MKDIRS, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public boolean renameTo(File_Instrumentation dest) {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_RENAME_TO, false, this, dest);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public boolean setReadOnly() {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_SET_READ_ONLY, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public boolean setWritable(boolean writable, boolean ownerOnly) {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_SET_WRITABLE, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public boolean setWritable(boolean writable) {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_SET_WRITABLE, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public boolean setReadable(boolean readable, boolean ownerOnly) {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_SET_READABLE, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public boolean setReadable(boolean readable) {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_SET_READABLE, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public boolean setExecutable(boolean executable, boolean ownerOnly) {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_SET_EXECUTABLE, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    public boolean setExecutable(boolean executable) {
        boolean isFileLockAcquired = acquireFileLockIfPossible();
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_SET_EXECUTABLE, false, this);
        }
        boolean returnVal = false;
        try {
            returnVal = Weaver.callOriginal();
        } finally {
            if (isFileLockAcquired) {
                releaseFileLock();
            }
        }
        registerExitOperation(isFileLockAcquired, operation);
        return returnVal;
    }

    // TODO: static createTempFile methods are not hooked since we don't have a way to protect against them.

    public abstract String getName();

    public abstract String getAbsolutePath();

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
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, ignored.getMessage()), ignored, File_Instrumentation.class.getName());
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
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, e.getMessage()), e, File_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, e.getMessage()), e, File_Instrumentation.class.getName());
            if (e instanceof NewRelicSecurityException) {
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, e.getMessage()), e, File_Instrumentation.class.getName());
                throw e;
            }
        }
        return null;
    }
}
