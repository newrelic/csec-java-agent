package com.k2cybersecurity.instrumentator.os;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import org.apache.commons.lang3.SystemUtils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;

public class OsVariablesInstance {

    public static final String LOGS = "logs";
    public static final String LANGUAGE_AGENT = "language-agent";
    public static final String CONFIG = "config";
    public static final String K_2_ROOT = "k2root";
    public static final String TMP = "tmp";

    private static OsVariablesInstance instance;

    private final static Object lock = new Object();

    private OSVariables osVariables;

    private OsVariablesInstance() {
        osVariables = new OSVariables();
        Path k2root = Paths.get(K2Instrumentator.K2_HOME, K_2_ROOT);
        if (!k2root.toFile().isDirectory()) {
            k2root.toFile().mkdir();
        }

        try {
            Files.setPosixFilePermissions(k2root, PosixFilePermissions.fromString("rwxrwxrwx"));
        } catch (Exception e) {
        }

        osVariables.setK2RootDir(k2root.toString());
        osVariables.setLogDirectory(Paths.get(k2root.toString(), LOGS, LANGUAGE_AGENT, K2Instrumentator.APPLICATION_UUID).toString());
        osVariables.setTmpDirectory(Paths.get(k2root.toString(), TMP, LANGUAGE_AGENT, K2Instrumentator.APPLICATION_UUID).toString());
        osVariables.setConfigPath(Paths.get(k2root.toString(), CONFIG).toString());
        osVariables.setPolicyConfigPath(Paths.get(k2root.toString(), CONFIG, LANGUAGE_AGENT).toString());

        if (SystemUtils.IS_OS_LINUX) {
            osVariables.setLinux(true);
            osVariables.setOs(IAgentConstants.LINUX);
        } else if (SystemUtils.IS_OS_MAC) {
            osVariables.setMac(true);
            osVariables.setOs(IAgentConstants.MAC);
        } else if (SystemUtils.IS_OS_WINDOWS) {
            osVariables.setWindows(true);
            osVariables.setOs(IAgentConstants.WINDOWS);
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
}
