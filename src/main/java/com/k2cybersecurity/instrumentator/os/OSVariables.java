package com.k2cybersecurity.instrumentator.os;

public class OSVariables {
    private String os;
    private Boolean isWindows = Boolean.FALSE;
    private Boolean isLinux = Boolean.FALSE;
    private Boolean isMac = Boolean.FALSE;
//    private String k2RootDir;
    private String logDirectory;
    private String tmpDirectory;
    private String osArch;
    private String configPath;
//    private String policyConfigPath;

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

    public String getConfigPath() {
        return configPath;
    }

    public void setConfigPath(String configPath) {
        this.configPath = configPath;
    }

    /*public String getPolicyConfigPath() {
        return policyConfigPath;
    }

    public void setPolicyConfigPath(String policyConfigPath) {
        this.policyConfigPath = policyConfigPath;
    }

    public String getK2RootDir() {
        return k2RootDir;
    }

    public void setK2RootDir(String k2RootDir) {
        this.k2RootDir = k2RootDir;
    }*/
}
