package com.k2cybersecurity.instrumentator.cve.scanner;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.os.OSVariables;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEPackageInfo;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEScanner;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class CVEServiceMac implements Runnable {

    private static final String ERROR_LOG = "Error : ";

    private static final String CANNOT_CREATE_DIRECTORY = "Cannot create directory : ";

    private static final String ERROR_PROCESS_TERMINATED = "Error Process terminated: {}";

    private static final String ERROR = "Error: {}";

    private static final String K2_VULNERABILITY_SCANNER_RESPONSE_ERROR = "K2 Vulnerability scanner response error : %s";

    private static final String K2_VULNERABILITY_SCANNER_RESPONSE = "K2 Vulnerability scanner response : %s";

    private static final String BASH_COMMAND = "bash";

    private static final String LOCALCVESERVICE_PATH = "localcveservice";

    public static final String KILL_PROCESS_TREE_COMMAND = "kill -9 -%s";
    public static final String KILLING_PROCESS_TREE_ROOTED_AT_S = "Killing process tree rooted at : %s";
    public static final String SETSID = "setsid";
    public static final String CORRUPTED_CVE_SERVICE_BUNDLE_DELETED = "Corrupted CVE service bundle deleted.";
    public static final String CAME_TO_EXTRACT_TAR_BUNDLE = "Came to extract tar bundle : ";
    public static final String MAC_SHELL = "bash ";
    public static final String PATH_TO_DEPENDENCY_CHECK = "/K2/dependency-check.sh";
    public static final String STARTUP_SH_PATH = "K2/startup.sh";

    private String nodeId;

    private boolean downloadTarBundle = false;

    private String kind;

    private String id;

    private boolean isEnvScan;

    private OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

    public CVEServiceMac(String nodeId, String kind, String id, boolean downloadTarBundle, boolean isEnvScan) {
        this.nodeId = nodeId;
        this.kind = kind;
        this.id = id;
        this.downloadTarBundle = downloadTarBundle;
        this.isEnvScan = isEnvScan;
    }

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    @Override
    public void run() {
        try {
            String packageParentDir = osVariables.getCvePackageBaseDir();
            CVEPackageInfo packageInfo = CVEComponentsService.getCVEPackageInfo();
            logger.log(LogLevel.DEBUG, "Package Info  : " + packageInfo.toString() + " :: " + CVEScannerPool.getInstance().getPackageInfo(), CVEServiceLinux.class.getName());
            boolean downloaded = false;
            if (downloadTarBundle || CVEScannerPool.getInstance().getPackageInfo() == null || StringUtils.equals(packageInfo.getLatestServiceVersion(), CVEScannerPool.getInstance().getPackageInfo().getLatestServiceVersion())) {
                downloaded = CVEComponentsService.downloadCVEPackage(packageInfo);
            }
            if (!downloaded) {
                return;
            }
            logger.log(LogLevel.DEBUG, "CVE package downloaded", CVEServiceLinux.class.getName());
            //Create untar Directory
            File parentDirectory = new File(packageParentDir, LOCALCVESERVICE_PATH);
            FileUtils.deleteQuietly(parentDirectory);
            if (!parentDirectory.exists()) {
                try {
                    parentDirectory.mkdirs();
                } catch (Throwable e) {
                    logger.log(LogLevel.ERROR, CANNOT_CREATE_DIRECTORY + parentDirectory, e,
                            CVEServiceMac.class.getName());
                    return;
                }
            }

            extractCVETar(CVEScannerPool.getInstance().getPackageInfo().getCvePackage(), parentDirectory);
            CVEComponentsService.setAllLinuxPermissions(parentDirectory.getAbsolutePath());

            logger.log(LogLevel.DEBUG, "CVE package extraction completed.", CVEServiceLinux.class.getName());

            StringBuilder dcCommand = new StringBuilder(MAC_SHELL);
            dcCommand.append(parentDirectory.getAbsolutePath());
            dcCommand.append(PATH_TO_DEPENDENCY_CHECK);

            String startupScriptPath = new File(packageParentDir, STARTUP_SH_PATH).getAbsolutePath();

            List<CVEScanner> scanDirs;
            if (isEnvScan) {
                scanDirs = CVEComponentsService.getLibScanDirs(packageParentDir);
            } else {
                scanDirs = CVEComponentsService.getAppScanDirs();
            }
            for (CVEScanner scanner : scanDirs) {
                File inputYaml = CVEComponentsService.createServiceYml(dcCommand.toString(), nodeId, scanner.getAppName(),
                        scanner.getAppSha256(), scanner.getDir(),
                        K2Instrumentator.APPLICATION_INFO_BEAN.getApplicationUUID(), scanner.getEnv(), kind, id, packageParentDir);
                List<String> paramList = Arrays.asList(SETSID, BASH_COMMAND, startupScriptPath,
                        inputYaml.getAbsolutePath());
                ProcessBuilder processBuilder = new ProcessBuilder(paramList);
                Process process = processBuilder.start();
                if (!process.waitFor(10, TimeUnit.MINUTES)) {
                    long pid = AgentUtils.getInstance().getProcessID(process);
                    if (pid > 1) {
                        logger.log(LogLevel.WARNING, String.format(KILLING_PROCESS_TREE_ROOTED_AT_S, pid), CVEServiceMac.class.getName());
                        AgentUtils.getInstance().incrementCVEServiceFailCount();
                        Runtime.getRuntime().exec(String.format(KILL_PROCESS_TREE_COMMAND, pid));
                    }
                } else if (process.exitValue() != 0) {
                    AgentUtils.getInstance().incrementCVEServiceFailCount();
                }
                List<String> response = IOUtils.readLines(process.getInputStream(), StandardCharsets.UTF_8);
                logger.log(LogLevel.INFO,
                        String.format(K2_VULNERABILITY_SCANNER_RESPONSE, StringUtils.join(response, StringUtils.LF)),
                        CVEServiceMac.class.getName());
                List<String> errResponse = IOUtils.readLines(process.getErrorStream(), StandardCharsets.UTF_8);
                logger.log(LogLevel.ERROR, String.format(K2_VULNERABILITY_SCANNER_RESPONSE_ERROR,
                        StringUtils.join(errResponse, StringUtils.LF)), CVEServiceMac.class.getName());
                try {
                    FileUtils.forceDelete(inputYaml);
                    logger.log(LogLevel.DEBUG, "CVE package deleted", CVEServiceLinux.class.getName());
                } catch (Throwable e) {
                }
            }
            CVEComponentsService.deleteAllComponents(parentDirectory, packageParentDir);
        } catch (InterruptedException e) {
            logger.log(LogLevel.ERROR, ERROR_PROCESS_TERMINATED, e, CVEServiceMac.class.getName());
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, ERROR, e, CVEServiceMac.class.getName());
        }

    }

    private boolean extractCVETar(File cveTar, File outputDir) {
        logger.log(LogLevel.DEBUG, CAME_TO_EXTRACT_TAR_BUNDLE + cveTar.getAbsolutePath(), CVEServiceMac.class.getName());
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
                    logger.log(LogLevel.ERROR, ERROR_LOG, e, CVEServiceMac.class.getName());
                }
            }
            return true;
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, ERROR_LOG, e, CVEServiceMac.class.getName());
            FileUtils.deleteQuietly(cveTar);
            logger.log(LogLevel.WARNING,
                    CORRUPTED_CVE_SERVICE_BUNDLE_DELETED, CVEServiceMac.class.getName());
        }

        return false;

    }
}
