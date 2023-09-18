package com.newrelic.agent.security.instrumentator.os;

import com.newrelic.agent.security.AgentConfig;
import com.newrelic.agent.security.AgentInfo;
import com.newrelic.agent.security.intcodeagent.logging.IAgentConstants;
import com.newrelic.agent.security.util.IUtilConstants;
import com.newrelic.api.agent.NewRelic;
import org.apache.commons.lang3.SystemUtils;

import java.io.File;
import java.nio.file.Paths;

public class OsVariablesInstance {

    public static final String LOGS = "logs";
    public static final String LANGUAGE_AGENT = "language-agent";

    public static final String TMP = "tmp";
    public static final String SNAPSHOTS = "snapshots";

    private static OsVariablesInstance instance;

    private final static Object lock = new Object();

    private OSVariables osVariables;

    private OsVariablesInstance() {
        osVariables = new OSVariables();
        /*Path k2root = Paths.get(AgentInfo.getInstance().getK2Home(), K_2_ROOT);
        if (!k2root.toFile().isDirectory()) {
            k2root.toFile().mkdir();
        }

        try {
            Files.setPosixFilePermissions(k2root, PosixFilePermissions.fromString("rwxrwxrwx"));
        } catch (Exception e) {
        }*/

//        osVariables.setK2RootDir(k2root.toString());
//        osVariables.setLogDirectory(Paths.get(k2root.toString(), LOGS, LANGUAGE_AGENT, AgentInfo.getInstance().getApplicationUUID()).toString());


        if(NewRelic.getAgent().getConfig().getValue("log_file_path") != null) {
            osVariables.setLogDirectory(Paths.get(NewRelic.getAgent().getConfig().getValue("log_file_path"), IUtilConstants.NR_SECURITY_HOME, LOGS).toString());
        } else {
            osVariables.setLogDirectory(Paths.get(AgentConfig.getInstance().getK2Home(), LOGS).toString());
        }
        osVariables.setTmpDirectory(Paths.get(AgentConfig.getInstance().getK2Home(), TMP, LANGUAGE_AGENT, AgentInfo.getInstance().getApplicationUUID()).toString());
        osVariables.setSnapshotDir(Paths.get(osVariables.getLogDirectory(), SNAPSHOTS).toString());
//        osVariables.setPolicyConfigPath(Paths.get(k2root.toString(), CONFIG, LANGUAGE_AGENT).toString());

        if (SystemUtils.IS_OS_LINUX) {
            osVariables.setLinux(true);
            osVariables.setOs(IAgentConstants.LINUX);
            osVariables.setRootDir(new File(File.separator));
        } else if (SystemUtils.IS_OS_MAC) {
            osVariables.setMac(true);
            osVariables.setOs(IAgentConstants.MAC);
            osVariables.setRootDir(new File(File.separator));
        } else if (SystemUtils.IS_OS_WINDOWS) {
            osVariables.setWindows(true);
            osVariables.setOs(IAgentConstants.WINDOWS);
            osVariables.setRootDir(new File("C:"));
        }
        String arch = SystemUtils.OS_ARCH;
        osVariables.setOsArch(getOsArch(arch));
    }

    private String getOsArch(String arch) {
        switch (arch) {
            case "aarch64":
            case "arm64":
                return "aarch64";
            case "amd64":
            case "x86_64":
            default:
                return "x64";
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

    /***
     * Do not call this method more than once.
     * @return
     */
    public static OsVariablesInstance instantiate() {
        instance = new OsVariablesInstance();
        return instance;
    }
}
