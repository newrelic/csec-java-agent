package com.nr.instrumentation.security.javaio;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.operation.FileIntegrityOperation;

import java.io.File;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

public class FileHelper {

    public static final String METHOD_NAME_FILEOUTPUTSTREAM_OPEN = "open";

    public static final String FILE_COPY = "copy";

    public static final String NEW_INPUT_STREAM = "newInputStream";

    public static final String NEW_OUTPUT_STREAM = "newOutputStream";

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "FILE_OPERATION_LOCK-";

    public static final List<String> ALLOWED_EXTENSIONS = Arrays.asList(new String[]{"css", "html", "htm", "jsp", "js", "classtmp"});

    public static final List<String> SOURCE_EXENSIONS = Arrays.asList(new String[]{"class", "jsp", "jar", "java"});
    public static final String METHOD_NAME_GET_BOOLEAN_ATTRIBUTES = "getBooleanAttributes";
    public static final String NEW_FILE_CHANNEL = "newFileChannel";
    public static final String NEW_ASYNCHRONOUS_FILE_CHANNEL = "newAsynchronousFileChannel";
    public static final String NEW_BYTE_CHANNEL = "newByteChannel";
    public static final String NEW_DIRECTORY_STREAM = "newDirectoryStream";
    public static final String CREATE_DIRECTORY = "createDirectory";
    public static final String CREATE_SYMBOLIC_LINK = "createSymbolicLink";
    public static final String CREATE_LINK = "createLink";
    public static final String DELETE = "delete";
    public static final String DELETE_IF_EXISTS = "deleteIfExists";
    public static final String MOVE = "move";
    public static final String SET_ATTRIBUTE = "setAttribute";

    public static final String METHOD_NAME_SET_PERMISSION = "setPermission";
    public static final String METHOD_NAME_CREATE_FILE_EXCLUSIVELY = "createFileExclusively";
    public static final String METHOD_NAME_DELETE = "delete";
    public static final String METHOD_NAME_LIST = "list";
    public static final String METHOD_NAME_CREATE_DIRECTORY = "createDirectory";
    public static final String METHOD_NAME_RENAME = "rename";
    public static final String METHOD_NAME_SETREADONLY = "setReadOnly";


    public static boolean skipExistsEvent(String filename) {
        String extension = getFileExtension(filename);
        if (!(NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled() &&
                NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()) &&
                extension != null && !extension.trim().isEmpty() &&
                (SOURCE_EXENSIONS.contains(extension) || ALLOWED_EXTENSIONS.contains(extension))) {
            return true;
        }

        return false;
    }

    public static String getFileExtension(File file) {
        String fileName = file.getName();
        return getFileExtension(fileName);
    }

    public static String getFileExtension(String fileName) {
        if (fileName.lastIndexOf(".") != -1 && fileName.lastIndexOf(".") != 0)
            return fileName.substring(fileName.lastIndexOf(".") + 1);
        else
            return "";
    }

    public static FileIntegrityOperation createEntryOfFileIntegrity(String fileName, String className, String methodName) {
        File file = Paths.get(fileName).toFile();
        String extension = getFileExtension(file);
        if (SOURCE_EXENSIONS.contains(extension) &&
                !NewRelicSecurity.getAgent().getSecurityMetaData().getFileLocalMap().containsKey(fileName)) {
            FileIntegrityOperation fbean = new FileIntegrityOperation(file.exists(), fileName, className,
                    methodName);
            NewRelicSecurity.getAgent().getSecurityMetaData().getFileLocalMap().put(fileName,
                    fbean);
            return fbean;
        }
        return null;
    }

    public static boolean isFileLockAcquired() {
        try {
            return NewRelicSecurity.isHookProcessingActive() &&
                    Boolean.TRUE.equals(NewRelicSecurity.getAgent().getSecurityMetaData().getCustomAttribute(getNrSecCustomAttribName(), Boolean.class));
        } catch (Throwable ignored) {}
        return false;
    }

    public static boolean acquireFileLockIfPossible() {
        try {
            if (NewRelicSecurity.isHookProcessingActive() &&
                    !isFileLockAcquired()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttribName(), true);
                return true;
            }
        } catch (Throwable ignored){}
        return false;
    }

    public static void releaseFileLock() {
        try {
            if(NewRelicSecurity.isHookProcessingActive()) {
                NewRelicSecurity.getAgent().getSecurityMetaData().addCustomAttribute(getNrSecCustomAttribName(), false);
            }
        } catch (Throwable ignored){}
    }

    private static String getNrSecCustomAttribName() {
        return NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
    }
}
