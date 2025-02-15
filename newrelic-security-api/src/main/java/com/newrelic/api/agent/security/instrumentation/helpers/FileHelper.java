package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.operation.FileIntegrityOperation;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

public class FileHelper {

    public static final String METHOD_NAME_FILEOUTPUTSTREAM_OPEN = "open";

    public static final String FILE_COPY = "copy";

    public static final String NEW_INPUT_STREAM = "newInputStream";

    public static final String NEW_OUTPUT_STREAM = "newOutputStream";

    public static final String NR_SEC_CUSTOM_ATTRIB_NAME = "FILE_OPERATION_LOCK-";

    public static final List<String> ALLOWED_EXTENSIONS = Arrays.asList(new String[]{"css", "html", "htm", "jsp", "js", "classtmp"});

    public static final List<String> SOURCE_EXENSIONS = Arrays.asList(new String[]{"class", "jsp", "jar", "java"});
    public static final String METHOD_NAME_GET_BOOLEAN_ATTRIBUTES = "getBooleanAttributes";
    public static final String METHOD_NAME_CREATE_NEW_FILE = "createNewFile";
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

    public static final String METHOD_NAME_SETPOSIXFILEPERMISSIONS = "setPosixFilePermissions";
    public static final String METHOD_NAME_CREATE_DIRECTORY = "createDirectory";
    public static final String METHOD_NAME_RENAME = "rename";
    public static final String METHOD_NAME_SETREADONLY = "setReadOnly";
    public static final String METHOD_NAME_DELETE_ON_EXIT = "deleteOnExit";
    public static final String METHOD_NAME_LISTFILES = "listFiles";
    public static final String METHOD_NAME_MKDIR = "mkdir";
    public static final String METHOD_NAME_MKDIRS = "mkdirs";
    public static final String METHOD_NAME_RENAME_TO = "renameTo";
    public static final String METHOD_NAME_SET_READ_ONLY = "setReadOnly";
    public static final String METHOD_NAME_SET_WRITABLE = "setWritable";
    public static final String METHOD_NAME_SET_READABLE = "setReadable";
    public static final String METHOD_NAME_SET_EXECUTABLE = "setExecutable";
    public static final String METHOD_NAME_EXISTS = "exists";
    public static final String FILE_OPERATION = "FILE_OPERATION";

    public static boolean skipExistsEvent(String filename) {
        boolean lockAcquired = ThreadLocalLockHelper.acquireLock();
        try {
            if(lockAcquired) {
                String extension = getFileExtension(filename);
                if (!(NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled() &&
                        NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled()) &&
                        extension != null && !extension.trim().isEmpty() &&
                        (SOURCE_EXENSIONS.contains(extension) || ALLOWED_EXTENSIONS.contains(extension))) {
                    return true;
                }
            }
        } finally {
            if(lockAcquired){
                ThreadLocalLockHelper.releaseLock();
            }
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
        boolean lockAcquired = ThreadLocalLockHelper.acquireLock();
        try {
            if(lockAcquired) {
                File file = Paths.get(fileName).toFile();
                String extension = getFileExtension(file);
                if (SOURCE_EXENSIONS.contains(extension) &&
                        !NewRelicSecurity.getAgent().getSecurityMetaData().getFileLocalMap().containsKey(fileName)) {
                    long lastModified = file.exists() ? file.lastModified() : -1;
                    String permissions = StringUtils.EMPTY;
                    try {
                        if (file.exists()) {
                            PosixFileAttributes fileAttributes = Files.readAttributes(Paths.get(file.getPath()), PosixFileAttributes.class);
                            Set<PosixFilePermission> permissionSet = fileAttributes.permissions();
                            permissions = permissionSet.toString();
                        }
                    } catch (IOException | InvalidPathException e) {
                    }
                    long fileLength = file.length();
                    FileIntegrityOperation fbean = new FileIntegrityOperation(file.exists(), fileName, className,
                            methodName, lastModified, permissions, fileLength);
                    NewRelicSecurity.getAgent().getSecurityMetaData().getFileLocalMap().put(fileName,
                            fbean);
                    return fbean;
                }
            }
        } catch (InvalidPathException ignored){}
        finally {
            if(lockAcquired){
                ThreadLocalLockHelper.releaseLock();
            }
        }
        return null;

    }

    public static void checkEntryOfFileIntegrity(List<String> fileNames) {
        boolean lockAcquired = ThreadLocalLockHelper.acquireLock();
        try {
            if(lockAcquired) {
                for (String fileName : fileNames) {
                    try {
                        File file = Paths.get(fileName).toFile();
                        if (NewRelicSecurity.getAgent().getSecurityMetaData().getFileLocalMap().containsKey(fileName)) {
                            FileIntegrityOperation fbean = NewRelicSecurity.getAgent().getSecurityMetaData().getFileLocalMap().get(fileName);
                            if (fbean.isIntegrityBreached(file)) {
                                //Lock release is required here, as this register operation inside lock is intentional
                                ThreadLocalLockHelper.releaseLock();
                                NewRelicSecurity.getAgent().getSecurityMetaData().getMetaData().setFromJumpRequiredInStackTrace(3);
                                NewRelicSecurity.getAgent().registerOperation(fbean);
                            }
                        }
                    } catch (InvalidPathException ignored) {}
                }
            }
        } finally {
            if(lockAcquired) {
                ThreadLocalLockHelper.releaseLock();
            }
        }
    }

    public static String getNrSecCustomAttribName() {
        return NR_SEC_CUSTOM_ATTRIB_NAME + Thread.currentThread().getId();
    }
}
