package com.k2cybersecurity.instrumentator.os;

import java.util.Optional;

public class OSVariables {
    private String os;
    private Boolean isWindows = Boolean.FALSE;
    private Boolean isLinux = Boolean.FALSE;
    private Boolean isMac = Boolean.FALSE;
    private String logDirectory;
    private String cvePackageBaseDir;

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

    public String getCvePackageBaseDir() {
        return cvePackageBaseDir;
    }

    public void setCvePackageBaseDir(String cvePackageBaseDir) {
        this.cvePackageBaseDir = cvePackageBaseDir;
    }
}
