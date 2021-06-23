package com.k2cybersecurity.instrumentator.os;

import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import org.apache.commons.lang3.SystemUtils;

public class OsVariablesInstance {

    public static final String TMP_K_2_LOGS = "/tmp/k2logs/";
    public static final String TMP = "/tmp/";
    public static final String C_USERS_PUBLIC_K_2_AGENT_LOGS = "C:\\Users\\Public\\k2agent\\logs\\";
    public static final String APP_DATA_LOCAL_K_2 = "\\AppData\\Local\\K2\\";
    private static OsVariablesInstance instance;

    private final static Object lock = new Object();

    private OSVariables osVariables;

    private OsVariablesInstance() {
        osVariables = new OSVariables();
        if (SystemUtils.IS_OS_LINUX) {
            osVariables.setLinux(true);
            osVariables.setLogDirectory(TMP_K_2_LOGS);
            osVariables.setCvePackageBaseDir(TMP);
            osVariables.setOs(IAgentConstants.LINUX);
        } else if (SystemUtils.IS_OS_MAC) {
            osVariables.setMac(true);
            osVariables.setLogDirectory(TMP_K_2_LOGS);
            osVariables.setCvePackageBaseDir(TMP);
            osVariables.setOs(IAgentConstants.MAC);
        } else if (SystemUtils.IS_OS_WINDOWS) {
            osVariables.setWindows(true);
            osVariables.setLogDirectory(C_USERS_PUBLIC_K_2_AGENT_LOGS);
            osVariables.setCvePackageBaseDir(SystemUtils.getUserHome() + APP_DATA_LOCAL_K_2);
            osVariables.setOs(IAgentConstants.WINDOWS);
        }
    }

    public OSVariables getOsVariables() {
        return osVariables;
    }

    public void setOsVariables(OSVariables osVariables) {
        this.osVariables = osVariables;
    }

    public static OsVariablesInstance getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new OsVariablesInstance();
                }
            }
        }
        return instance;
    }
}
