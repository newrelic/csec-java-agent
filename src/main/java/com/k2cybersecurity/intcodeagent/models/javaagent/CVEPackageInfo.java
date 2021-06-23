package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.io.File;

@JsonIgnoreProperties(ignoreUnknown = true)
public class CVEPackageInfo {

    private String platform;

    private String latestServiceVersion;

    private String latestServiceSHA256;

    private String latestProcessedServiceSHA256;

    private File cvePackage;

    public CVEPackageInfo() {
    }

    public String getPlatform() {
        return platform;
    }

    public void setPlatform(String platform) {
        this.platform = platform;
    }

    public String getLatestServiceVersion() {
        return latestServiceVersion;
    }

    public void setLatestServiceVersion(String latestServiceVersion) {
        this.latestServiceVersion = latestServiceVersion;
    }

    public String getLatestServiceSHA256() {
        return latestServiceSHA256;
    }

    public void setLatestServiceSHA256(String latestServiceSHA256) {
        this.latestServiceSHA256 = latestServiceSHA256;
    }

    public String getLatestProcessedServiceSHA256() {
        return latestProcessedServiceSHA256;
    }

    public void setLatestProcessedServiceSHA256(String latestProcessedServiceSHA256) {
        this.latestProcessedServiceSHA256 = latestProcessedServiceSHA256;
    }

    public File getCvePackage() {
        return cvePackage;
    }

    public void setCvePackage(File cvePackage) {
        this.cvePackage = cvePackage;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);

    }
}
