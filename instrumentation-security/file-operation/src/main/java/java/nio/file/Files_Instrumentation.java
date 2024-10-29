package java.nio.file;

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

import java.io.File;
import java.io.File_Instrumentation;
import java.io.IOException;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Weave(type = MatchType.BaseClass, originalName = "java.nio.file.Files")
public class Files_Instrumentation {

    public static Path setPosixFilePermissions(Path path,
                                               Set<PosixFilePermission> perms)
            throws IOException
    {
        boolean isFileLockAcquired = acquireFileLockIfPossible(VulnerabilityCaseType.FILE_OPERATION);
        AbstractOperation operation = null;
        if (isFileLockAcquired) {
            operation = preprocessSecurityHook(false, FileHelper.METHOD_NAME_SETPOSIXFILEPERMISSIONS, false, path.toFile());
        }
        Path returnVal = null;
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
        } catch (Throwable ignored) {
            NewRelicSecurity.getAgent().log(LogLevel.FINEST, String.format(GenericHelper.EXIT_OPERATION_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, ignored.getMessage()), ignored, File_Instrumentation.class.getName());
        }
    }

    private static AbstractOperation preprocessSecurityHook(boolean isBooleanAttributesCall, String methodName, boolean isLowSeverityHook,
                                                            File... files) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() ||
                    NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
                    || files == null || files.length == 0
            ) {
                return null;
            }
            List<String> fileNames = new ArrayList<>(files.length);
            for (File file : files) {
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
                NewRelicSecurity.getAgent().log(LogLevel.WARNING, String.format(GenericHelper.SECURITY_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, e.getMessage()), e, File_Instrumentation.class.getName());
                throw e;
            }
            NewRelicSecurity.getAgent().log(LogLevel.SEVERE, String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, e.getMessage()), e, File_Instrumentation.class.getName());
            NewRelicSecurity.getAgent().reportIncident(LogLevel.SEVERE , String.format(GenericHelper.REGISTER_OPERATION_EXCEPTION_MESSAGE, FileHelper.FILE_OPERATION, e.getMessage()), e, File_Instrumentation.class.getName());
        }
        return null;
    }
}
