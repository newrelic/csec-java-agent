package com.newrelic.agent.security.instrumentator.os;

import java.io.File;

public class OSVariables {
    private String os;
    private Boolean isWindows = Boolean.FALSE;
    private Boolean isLinux = Boolean.FALSE;
    private Boolean isMac = Boolean.FALSE;

    private String logDirectory;
    private String tmpDirectory;

    private String snapshotDir;

    private String osArch;

    private File rootDir;

    private File logFile;

    private File initLogFile;

    public String getOs() {
        return os;
    }

    public void setOs(String os) {
        this.os = os;
    }

    public Boolean getWindows() {
        return isWindows;
    }

    public void setWindows(Boolean windows) {
        isWindows = windows;
    }

    public Boolean getLinux() {
        return isLinux;
    }

    public void setLinux(Boolean linux) {
        isLinux = linux;
    }

    public Boolean getMac() {
        return isMac;
    }

    public void setMac(Boolean mac) {
        isMac = mac;
    }

    public String getLogDirectory() {
        return logDirectory;
    }

    public void setLogDirectory(String logDirectory) {
        this.logDirectory = logDirectory;
    }

    public String getTmpDirectory() {
        return tmpDirectory;
    }

    public String getOsArch() {
        return osArch;
    }

    public void setOsArch(String osArch) {
        this.osArch = osArch;
    }

    public void setTmpDirectory(String tmpDirectory) {
        this.tmpDirectory = tmpDirectory;
    }

    public File getRootDir() {
        return rootDir;
    }

    public void setRootDir(File rootDir) {
        this.rootDir = rootDir;
    }

    public String getSnapshotDir() {
        return snapshotDir;
    }

    public void setSnapshotDir(String snapshotDir) {
        this.snapshotDir = snapshotDir;
    }

    public File getLogFile() {
        return logFile;
    }

    public void setLogFile(File logFile) {
        this.logFile = logFile;
    }

    public File getInitLogFile() {
        return initLogFile;
    }

    public void setInitLogFile(File initLogFile) {
        this.initLogFile = initLogFile;
    }

}
