package com.k2cybersecurity.instrumentator.cve.scanner;

public interface ICVEConstants {
    String LOCALCVESERVICE_LINUX_TAR_REGEX = "localcveservice-(.*)\\.linux\\.tar";
    String LOCALCVESERVICE_WIN_ZIP_REGEX = "localcveservice-(.*)\\.win\\.zip";
    String LOCALCVESERVICE_MAC_TAR_REGEX = "localcveservice-(.*)\\.mac\\.tar";
    String LOCALCVESERVICE = "localcveservice-";
    String CVE_PACKAGE_DELETED = "CVE package deleted";
    String CVE_PACKAGE_EXTRACTION_COMPLETED = "CVE package extraction completed.";
    String CVE_PACKAGE_DOWNLOADED = "CVE package downloaded";
    String PACKAGE_INFO_LOGGER = "Package Info  : %s :: %s";
    String DC_TRIGGER_LOG = "dc-trigger.log";
}
