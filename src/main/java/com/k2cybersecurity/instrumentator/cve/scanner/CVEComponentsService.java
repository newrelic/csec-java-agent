package com.k2cybersecurity.instrumentator.cve.scanner;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.CollectorConfigurationUtils;
import com.k2cybersecurity.instrumentator.utils.HashGenerator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.logging.IAgentConstants;
import com.k2cybersecurity.intcodeagent.models.javaagent.ApplicationScanComponentData;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEComponent;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEScanner;
import com.k2cybersecurity.intcodeagent.models.javaagent.ScanComponentData;
import com.k2cybersecurity.intcodeagent.websocket.FtpClient;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.net.ftp.FTPClient;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.*;

public class CVEComponentsService {

    public static final String K_2_JAVA_AGENT_1_0_0_JAR_WITH_DEPENDENCIES_JAR = "K2-JavaAgent-1.0.0-jar-with-dependencies.jar";
    private static final String TMP_LIBS = "libs-";
    public static final String FAILED_TO_PROCESS_LIB_PATH = "Failed to process lib path  : ";
    public static final String FAILED_TO_PROCESS_DIRECTORY = "Failed to process directory : ";
    public static final String COLON_SEPERATOR = " : ";

	private static final String JAR_EXTENSION = ".jar";

	private static final String JAR_EXT = "jar";

    private static final String YML_TEMPLATE = "# path to dependency check tool.\r\n"
            + "dependencycheck.command: sh /tmp/localcveservice/dist/dependency-check.sh\r\n"
            + "# connecting back to k2agent.\r\n" + "k2agent.websocket: ws://%s/\r\n" + "k2agent.nodeId: %s\r\n"
            + "k2agent.identifier.kind: %s\r\n" + "k2agent.identifier.id: %s\r\n"
            + "#----- following are file scan specific options\r\n" + "k2agent.scan.mode: file\r\n"
            + "k2agent.application: %s\r\n" + "k2agent.applicationUuid: %s\r\n" + "k2agent.applicationSha256: %s\r\n"
            + "k2agent.scanPath: %s\r\n" + "k2agent.isEnv: %s\r\n";
	
	private static Set<CVEComponent> envCveComponents = new HashSet<>();
	
	static {
		envCveComponents = getCVEComponents(getLibPaths());
	}

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	public static ScanComponentData getAllComponents(DeployedApplication deployedApplication) {
		Set<String> appJarPaths = getAllJarsFromApp(deployedApplication.getDeployedPath());
		ScanComponentData scanComponentData = new ScanComponentData(K2Instrumentator.APPLICATION_UUID);
		ApplicationScanComponentData applicationScanComponentData = new ApplicationScanComponentData(
				deployedApplication.getAppName(), deployedApplication.getSha256());
		applicationScanComponentData.setComponents(getCVEComponents(appJarPaths));
		envCveComponents.removeAll(applicationScanComponentData.getComponents());
		scanComponentData.setEnvComponents(envCveComponents);
		scanComponentData.setDeployedApplications(Collections.singleton(applicationScanComponentData));
		return scanComponentData;
	}

	private static Set<CVEComponent> getCVEComponents(Set<String> libPaths) {
		Set<CVEComponent> cveComponents = new HashSet();

		for (String path : libPaths) {
			File file = new File(path);
			if (file.length() != 0) {
				cveComponents.add(new CVEComponent(file.getName(), HashGenerator.getChecksum(file)));
			}
		}

		return cveComponents;
	}

	private static Set<String> getAllJarsFromApp(String deployedPath) {
		Set<String> jars = new HashSet<>();
		File app = new File(deployedPath);
		if (app.isFile()) {
			jars.add(deployedPath);
		} else if (app.isDirectory()) {
			FileUtils.listFiles(app, new String[] { JAR_EXT }, true)
					.forEach(jarFile -> jars.add(jarFile.getAbsolutePath()));
		}
		return jars;
	}

	public static Set<String> getLibPaths() {
		Set<String> libPaths = new HashSet<>();
		if (!K2Instrumentator.APPLICATION_INFO_BEAN.getLibraryPath().isEmpty()) {
			for (String path : K2Instrumentator.APPLICATION_INFO_BEAN.getLibraryPath()) {
				if (StringUtils.endsWith(path, JAR_EXTENSION) && !StringUtils.endsWithIgnoreCase(path, "K2-JavaAgent-1.0.0-jar-with-dependencies.jar")) {
					libPaths.add(path);
				} else if (new File(path).isDirectory()) {
					FileUtils.listFiles(new File(path), new String[]{JAR_EXT}, true)
							.forEach(jarFile -> libPaths.add(jarFile.getAbsolutePath()));
				}
			}
		}
		return libPaths;
	}

    protected static List<CVEScanner> getLibScanDirs(String cvePackageDir) {
        List<CVEScanner> scanners = new ArrayList<>();
        List<String> libPaths = new ArrayList<>();
        if (!K2Instrumentator.APPLICATION_INFO_BEAN.getLibraryPath().isEmpty()) {
            for (String path : K2Instrumentator.APPLICATION_INFO_BEAN.getLibraryPath()) {
                if (StringUtils.endsWith(path, JAR_EXTENSION) && !StringUtils.endsWithIgnoreCase(path, K_2_JAVA_AGENT_1_0_0_JAR_WITH_DEPENDENCIES_JAR)) {
                    libPaths.add(path);
                } else if (new File(path).isDirectory()) {
                    FileUtils.listFiles(new File(path), new String[]{JAR_EXT}, true)
                            .forEach(jarFile -> libPaths.add(jarFile.getAbsolutePath()));
                }
            }
        }

        if (!libPaths.isEmpty()) {
            CVEScanner cveScanner = createLibTmpDir(cvePackageDir, libPaths, K2Instrumentator.APPLICATION_INFO_BEAN.getBinaryName(),
                    K2Instrumentator.APPLICATION_INFO_BEAN.getApplicationUUID());
            if (cveScanner != null) {
                scanners.add(cveScanner);
            }
        }
        return scanners;
    }

    private static CVEScanner createLibTmpDir(String cvePackageDir, List<String> libPaths, String binaryName, String applicationUUID) {
        File directory = new File(cvePackageDir, TMP_LIBS + applicationUUID);
        try {
            FileUtils.forceMkdir(directory);
            for (String path : libPaths) {
                try {
                    logger.log(LogLevel.DEBUG, "Add jar : " + path, CVEServiceWindows.class.getName());
                    FileUtils.copyFileToDirectory(new File(path), directory, true);
                } catch (Exception e) {
                    logger.log(LogLevel.DEBUG, FAILED_TO_PROCESS_LIB_PATH + directory + COLON_SEPERATOR + path, e, CVEServiceWindows.class.getName());
                }
            }
            return new CVEScanner(binaryName + " Env Libs " + applicationUUID,
                    HashGenerator.getSHA256ForDirectory(directory.getAbsolutePath()), directory.getAbsolutePath(), true);
        } catch (Exception e) {
            logger.log(LogLevel.DEBUG, FAILED_TO_PROCESS_DIRECTORY + directory, e, CVEServiceWindows.class.getName());
        }
        return null;
    }

    protected static List<CVEScanner> getAppScanDirs() {
        List<CVEScanner> scanners = new ArrayList<>();
        List<String> appJarNames = new ArrayList<>();

        if (K2Instrumentator.APPLICATION_INFO_BEAN.getServerInfo().getDeployedApplications() != null) {
            for (Object obj : K2Instrumentator.APPLICATION_INFO_BEAN.getServerInfo().getDeployedApplications()) {
                DeployedApplication deployedApplication = (DeployedApplication) obj;
                if (!AgentUtils.getInstance().getScannedDeployedApplications().contains(deployedApplication)) {
                    scanners.add(new CVEScanner(deployedApplication.getAppName(), deployedApplication.getSha256(),
                            deployedApplication.getDeployedPath(), false));
                    if (StringUtils.endsWith(deployedApplication.getDeployedPath(), JAR_EXTENSION) && !StringUtils.endsWithIgnoreCase(deployedApplication.getDeployedPath(), K_2_JAVA_AGENT_1_0_0_JAR_WITH_DEPENDENCIES_JAR)) {
                        appJarNames.add(Paths.get(deployedApplication.getDeployedPath()).toString());
                    }
                    AgentUtils.getInstance().addScannedDeployedApplications(deployedApplication);
                }
            }
        }

        return scanners;
    }

    protected static void deleteAllComponents(File cveDir, String cvePackageDir) {
        try {
            FileUtils.forceDelete(cveDir);
        } catch (IOException e) {
        }

        try {
            FileUtils.forceDelete(new File(cvePackageDir, TMP_LIBS + K2Instrumentator.APPLICATION_UUID));
        } catch (IOException e) {
        }
    }

    protected static void setAllLinuxPermissions(String loc) {
        try {
            Runtime.getRuntime().exec(String.format("chmod a+rwx -R %s", loc)).waitFor();
        } catch (Throwable e) {
        }
    }

    protected static boolean downloadCVEPackage(FTPClient client, File cveFile, boolean downloadTarBundle) {
        boolean download = false;
        if (downloadTarBundle || !cveFile.exists()) {
            FileUtils.deleteQuietly(cveFile);
            download = FtpClient.downloadFile(client, cveFile.getName(), cveFile.getAbsolutePath());
            if (!download) {
                logger.log(LogLevel.ERROR, "Unable to download Local CVE Service tar from IC", CVEServiceWindows.class.getName());
                FileUtils.deleteQuietly(cveFile);
                return false;
            }
        } else {
            logger.log(LogLevel.INFO, "Local CVE Service tar bundle already present. No need for download from IC", CVEServiceWindows.class.getName());
        }
        return download;
    }

    protected static File createServiceYml(String nodeId, String appName, String appSha256,
                                           String scanPath, String applicationUUID, Boolean env, String kind, String id, String packageParentDir) throws IOException {
        //TODO update YAML add WS headers (cid, api accessor token)
        String yaml = String.format(YML_TEMPLATE, String.format("%s:%s", CollectorConfigurationUtils.getInstance().getCollectorConfig().getK2ServiceInfo().getServiceEndpointAddress(),
                CollectorConfigurationUtils.getInstance().getCollectorConfig().getK2ServiceInfo().getServiceEndpointPort()),
                nodeId, kind, id, appName, applicationUUID, appSha256,
                scanPath, env);
        File yml = new File(packageParentDir, "service-input.yml");
        logger.log(LogLevel.INFO, "input yml : " + yaml, CVEServiceWindows.class.getName());
        FileUtils.write(yml, yaml, StandardCharsets.UTF_8);
        return yml;
    }

    public static String getPackageRegex(String platform) {
        switch (platform) {
            case IAgentConstants.LINUX:
                return "localcveservice-(.*)\\.linux\\.tar";
            case IAgentConstants.MAC:
                return "localcveservice-(.*)\\.mac\\.tar";
            case IAgentConstants.WINDOWS:
                return "localcveservice-(.*)\\.win\\.zip";
            default:
                return StringUtils.EMPTY;
        }
    }
}
