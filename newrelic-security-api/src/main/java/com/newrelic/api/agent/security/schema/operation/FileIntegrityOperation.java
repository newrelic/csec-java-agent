package com.newrelic.api.agent.security.schema.operation;

import com.newrelic.api.agent.security.instrumentation.helpers.ThreadLocalLockHelper;
import com.newrelic.api.agent.security.schema.AbstractOperation;
import com.newrelic.api.agent.security.schema.StringUtils;
import com.newrelic.api.agent.security.schema.VulnerabilityCaseType;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

public class FileIntegrityOperation extends AbstractOperation {

    private Boolean exists;
    private String userFileName;
    private String userMethodName;
    private String currentMethod;
    private Integer lineNumber;
    private String fileName;

    private Long lastModified;

    private String permissionString;

    private Long length;

    public FileIntegrityOperation(Boolean exists, String fileName, String className, String methodName, Long lastModified, String permissionString, Long length) {
        super(className, methodName);
        this.setCaseType(VulnerabilityCaseType.FILE_INTEGRITY);
        this.exists = exists;
        this.setFileName(fileName);
        this.lastModified = lastModified;
        this.permissionString = permissionString;
        this.length = length;
    }

    /**
     * @return the exists
     */
    public Boolean getExists() {
        return exists;
    }

    /**
     * @param exists the exists to set
     */
    public void setExists(Boolean exists) {
        this.exists = exists;
    }

    /**
     * @return the userFileName
     */
    public String getUserFileName() {
        return userFileName;
    }

    /**
     * @param userFileName the userFileName to set
     */
    public void setUserFileName(String userFileName) {
        this.userFileName = userFileName;
    }

    /**
     * @return the userMethodName
     */
    public String getUserMethodName() {
        return userMethodName;
    }

    /**
     * @param userMethodName the userMethodName to set
     */
    public void setUserMethodName(String userMethodName) {
        this.userMethodName = userMethodName;
    }

    /**
     * @return the currentMethod
     */
    public String getCurrentMethod() {
        return currentMethod;
    }

    /**
     * @param currentMethod the currentMethod to set
     */
    public void setCurrentMethod(String currentMethod) {
        this.currentMethod = currentMethod;
    }

    /**
     * @return the lineNumber
     */
    public Integer getLineNumber() {
        return lineNumber;
    }

    /**
     * @param lineNumber the lineNumber to set
     */
    public void setLineNumber(Integer lineNumber) {
        this.lineNumber = lineNumber;
    }

    @Override
    public boolean isEmpty() {
        return (fileName == null || fileName.trim().isEmpty());
    }

    /**
     * @return the fileName
     */
    public String getFileName() {
        return fileName;
    }

    /**
     * @param fileName the fileName to set
     */
    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public Long getLastModified() {
        return lastModified;
    }

    public void setLastModified(Long lastModified) {
        this.lastModified = lastModified;
    }

    public String getPermissionString() {
        return permissionString;
    }

    public void setPermissionString(String permissionString) {
        this.permissionString = permissionString;
    }

    public boolean isIntegrityBreached(File file){
        boolean lockAcquired = ThreadLocalLockHelper.acquireLock();
        try {
            if(lockAcquired) {
                Boolean exists = file.exists();
                long lastModified = exists ? file.lastModified() : -1;
                String permissions = StringUtils.EMPTY;
                long length = file.length();
                if (exists) {
                    PosixFileAttributes fileAttributes = Files.readAttributes(Paths.get(file.getPath()), PosixFileAttributes.class);
                    Set<PosixFilePermission> permissionSet = fileAttributes.permissions();
                    permissions = permissionSet.toString();
                }
                return (exists != this.exists || lastModified != this.lastModified || !StringUtils.equals(permissions, this.permissionString) || length != this.length);
            }
        } catch (IOException e) {
        } finally {
            if(lockAcquired) {
                ThreadLocalLockHelper.releaseLock();
            }
        }
        return false;
    }
}
