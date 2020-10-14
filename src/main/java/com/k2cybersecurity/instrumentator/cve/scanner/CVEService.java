package com.k2cybersecurity.instrumentator.cve.scanner;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.HashGenerator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEScanner;
import com.k2cybersecurity.intcodeagent.websocket.FtpClient;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class CVEService implements Runnable {

    private static final String ENV_LIBS = " Env Libs ";

    private static final String TMP_LIBS = "/tmp/libs-";

    private static final String JAR_EXTENSION = ".jar";

    private static final String JAR_EXT = "jar";

    private static final String INPUT_YML_LOG = "input yml : ";

    private static final String SERVICE_INPUT_YML = "service-input.yml";

    private static final String TMP_DIR = "/tmp";

    private static final String ERROR_LOG = "Error : ";

    private static final String CANNOT_CREATE_DIRECTORY = "Cannot create directory : ";

    private static final String CHMOD_A_RWX_R_S = "chmod a+rwx -R %s";

    private static final String ERROR_PROCESS_TERMINATED = "Error Process terminated: {}";

    private static final String ERROR = "Error: {}";

    private static final String K2_VULNERABILITY_SCANNER_RESPONSE_ERROR = "K2 Vulnerability scanner response error : %s";

    private static final String K2_VULNERABILITY_SCANNER_RESPONSE = "K2 Vulnerability scanner response : %s";

    private static final String BASH_COMMAND = "bash";

    private static final String TMP_LOCALCVESERVICE_DIST_STARTUP_SH = "/tmp/localcveservice/dist/startup.sh";

    private static final String TMP_LOCALCVESERVICE_PATH = "/tmp/localcveservice";

    private static final String CVE_SERVICE_TAR_DOESN_T_EXISTS = "CVE-Service Tar doesn't exists.";

    private static final String TMP_LOCALCVESERVICE_TAR = "/tmp/localcveservice.tar";
    public static final String KILL_PROCESS_TREE_COMMAND = "kill -9 -%s";
    public static final String KILLING_PROCESS_TREE_ROOTED_AT_S = "Killing process tree rooted at : %s";

    private String nodeId;

    private boolean downloadTarBundle = false;

    public CVEService(String nodeId, boolean downloadTarBundle) {
        this.nodeId = nodeId;
        this.downloadTarBundle = downloadTarBundle;
    }

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    private static final String YML_TEMPLATE = "# path to dependency check tool.\r\n"
            + "dependencycheck.command: sh /tmp/localcveservice/dist/dependency-check.sh\r\n"
            + "# connecting back to k2agent.\r\n" + "k2agent.websocket: ws://%s:54321/\r\n" + "k2agent.nodeId: %s\r\n"
            + "#----- following are file scan specific options\\r\n" + "k2agent.scan.mode: file\r\n"
            + "k2agent.application: %s\r\n" + "k2agent.applicationUuid: %s\r\n" + "k2agent.applicationSha256: %s\r\n"
            + "k2agent.scanPath: %s\r\n";

    @Override
    public void run() {
        try {
            File cveTar = new File(TMP_LOCALCVESERVICE_TAR);

            boolean downlaoded = downloadCVEJar(cveTar, TMP_LOCALCVESERVICE_PATH);
            if (!downlaoded) {
                return;
            }
            for (CVEScanner scanner : getAllScanDirs()) {
                File inputYaml = createServiceYml(TMP_LOCALCVESERVICE_PATH, nodeId, scanner.getAppName(),
                        scanner.getAppSha256(), scanner.getDir(),
                        K2Instrumentator.APPLICATION_INFO_BEAN.getApplicationUUID());
                List<String> paramList = Arrays.asList(BASH_COMMAND, TMP_LOCALCVESERVICE_DIST_STARTUP_SH,
                        inputYaml.getAbsolutePath());
                ProcessBuilder processBuilder = new ProcessBuilder(paramList);
                Process process = processBuilder.start();
                if (!process.waitFor(10, TimeUnit.MINUTES)) {
                    long pid = AgentUtils.getInstance().getProcessID(process);
                    if (pid > 1) {
                        logger.log(LogLevel.WARNING, String.format(KILLING_PROCESS_TREE_ROOTED_AT_S, pid), CVEService.class.getName());
                        Runtime.getRuntime().exec(String.format(KILL_PROCESS_TREE_COMMAND, pid));
                    }
                }
                List<String> response = IOUtils.readLines(process.getInputStream(), StandardCharsets.UTF_8);
                logger.log(LogLevel.INFO,
                        String.format(K2_VULNERABILITY_SCANNER_RESPONSE, StringUtils.join(response, StringUtils.LF)),
                        CVEService.class.getName());
                List<String> errResponse = IOUtils.readLines(process.getErrorStream(), StandardCharsets.UTF_8);
                logger.log(LogLevel.ERROR, String.format(K2_VULNERABILITY_SCANNER_RESPONSE_ERROR,
                        StringUtils.join(errResponse, StringUtils.LF)), CVEService.class.getName());
                try {
                    FileUtils.forceDelete(inputYaml);
                } catch (Throwable e) {
                }
            }
            deleteAllComponents(cveTar, TMP_LOCALCVESERVICE_PATH);
        } catch (InterruptedException e) {
            logger.log(LogLevel.ERROR, ERROR_PROCESS_TERMINATED, e, CVEService.class.getName());
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, ERROR, e, CVEService.class.getName());
        }

    }

    protected void deleteAllComponents(File cveTar, String cveDir) {
        try {
            FileUtils.forceDelete(new File(cveDir));
        } catch (IOException e) {
        }

        try {
            FileUtils.forceDelete(new File(TMP_LIBS + K2Instrumentator.APPLICATION_UUID));
        } catch (IOException e) {
        }

		try {
			FileUtils.forceDelete(new File(TMP_DIR, K2Instrumentator.APPLICATION_UUID));
		} catch (IOException e) {
		}
    }

    private void setAllPermissions(String loc) {
        try {
            Runtime.getRuntime().exec(String.format(CHMOD_A_RWX_R_S, loc)).waitFor();
        } catch (Throwable e) {
        }
    }

    private boolean downloadCVEJar(File cveTar, String outputDir) {
        boolean download = false;
        if (downloadTarBundle || !cveTar.exists()) {
            cveTar.delete();
            download = FtpClient.downloadFile(cveTar.getName(), cveTar.getAbsolutePath());
            if (!download) {
                logger.log(LogLevel.ERROR, "Unable to download Local CVE Service tar from IC", CVEService.class.getName());
                return false;
            }
        } else {
			logger.log(LogLevel.INFO, "Local CVE Service tar bundle already present. No need for download from IC", CVEService.class.getName());
		}
        File parentDirectory = new File(outputDir);
        FileUtils.deleteQuietly(parentDirectory);
        if (!parentDirectory.exists()) {
            try {
                parentDirectory.mkdirs();
            } catch (Throwable e) {
                logger.log(LogLevel.ERROR, CANNOT_CREATE_DIRECTORY + parentDirectory, e,
                        CVEService.class.getName());
                return false;
            }
        }

        try (TarArchiveInputStream inputStream = new TarArchiveInputStream(new FileInputStream(cveTar),
                StandardCharsets.UTF_8.name())) {
            TarArchiveEntry entry;
            while ((entry = inputStream.getNextTarEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                File curfile = new File(outputDir, entry.getName());
                File parent = curfile.getParentFile();
                if (!parent.exists()) {
                    parent.mkdirs();
                }
                try (FileOutputStream outputStream = new FileOutputStream(curfile)) {
                    IOUtils.copy(inputStream, outputStream);
                } catch (Throwable e) {
                    logger.log(LogLevel.ERROR, ERROR_LOG, e, CVEService.class.getName());
                }
            }
            setAllPermissions(parentDirectory.getAbsolutePath());
            return true;
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, ERROR_LOG, e, CVEService.class.getName());
        }

        return false;

    }

    protected File createServiceYml(String cveServicePath, String nodeId, String appName, String appSha256,
                                    String scanPath, String applicationUUID) throws IOException {
        String yaml = String.format(YML_TEMPLATE, K2Instrumentator.hostip, nodeId, appName, applicationUUID, appSha256,
                scanPath);
        File yml = new File(TMP_DIR, SERVICE_INPUT_YML);
        logger.log(LogLevel.INFO, INPUT_YML_LOG + yaml, CVEService.class.getName());
        FileUtils.write(yml, yaml, StandardCharsets.UTF_8);
        return yml;
    }

    protected List<CVEScanner> getAllScanDirs() {
    	List<CVEScanner> scanners = new ArrayList<>();
    	List<String> appJarNames = new ArrayList<>();
    	
    	if (K2Instrumentator.APPLICATION_INFO_BEAN.getServerInfo().getDeployedApplications() != null) {
            for (Object obj : K2Instrumentator.APPLICATION_INFO_BEAN.getServerInfo().getDeployedApplications()) {
                DeployedApplication deployedApplication = (DeployedApplication) obj;
                if (!AgentUtils.getInstance().getScannedDeployedApplications().contains(deployedApplication)) {
                    scanners.add(new CVEScanner(deployedApplication.getAppName(), deployedApplication.getSha256(),
                            deployedApplication.getDeployedPath()));
                    if(StringUtils.endsWith(deployedApplication.getDeployedPath(), JAR_EXTENSION)) {
                    	appJarNames.add(Paths.get(deployedApplication.getDeployedPath()).toString());
                    }
                    AgentUtils.getInstance().addScannedDeployedApplications(deployedApplication);
                }
            }
        }
    	
        List<String> libPaths = new ArrayList<>();
        if (!K2Instrumentator.APPLICATION_INFO_BEAN.getLibraryPath().isEmpty()) {
            for (String path : K2Instrumentator.APPLICATION_INFO_BEAN.getLibraryPath()) {
                if (StringUtils.endsWith(path, JAR_EXTENSION)) {
                    libPaths.add(path);
                } else if (new File(path).isDirectory()) {
                    FileUtils.listFiles(new File(path), new String[]{JAR_EXT}, true)
                            .forEach(jarFile -> libPaths.add(jarFile.getAbsolutePath()));
                }
            }
            libPaths.removeAll(appJarNames);
        }
        
        if (!libPaths.isEmpty()) {
            CVEScanner cveScanner = createLibTmpDir(libPaths, K2Instrumentator.APPLICATION_INFO_BEAN.getBinaryName(),
                    K2Instrumentator.APPLICATION_INFO_BEAN.getApplicationUUID());
            scanners.add(cveScanner);
        }

        
        return scanners;
    }

    private CVEScanner createLibTmpDir(List<String> libPaths, String binaryName, String applicationUUID) {
        File directory = new File(TMP_LIBS + applicationUUID);
        try {
            FileUtils.forceMkdir(directory);
            for (String path : libPaths) {
//				logger.log(LogLevel.DEBUG, "Add jar : "+path, CVEService.class.getName());
                FileUtils.copyFileToDirectory(new File(path), directory, true);
            }
            return new CVEScanner(binaryName + ENV_LIBS + applicationUUID,
                    HashGenerator.getSHA256ForDirectory(directory.getAbsolutePath()), directory.getAbsolutePath());
        } catch (IOException e) {
        }
        return null;
    }
}
