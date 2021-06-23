package com.k2cybersecurity.instrumentator.cve.scanner;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.os.OSVariables;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEPackageInfo;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEScanner;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.SystemUtils;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class CVEServiceWindows implements Runnable {

    static final String TMP_DIR = SystemUtils.getUserHome() + "\\AppData\\Local\\K2\\";

    private static final String CANNOT_CREATE_DIRECTORY = "Cannot create directory : ";

    private static final String ERROR_PROCESS_TERMINATED = "Error Process terminated: {}";

    private static final String ERROR = "Error: {}";

    private static final String K2_VULNERABILITY_SCANNER_RESPONSE_ERROR = "K2 Vulnerability scanner response error : %s";

    private static final String K2_VULNERABILITY_SCANNER_RESPONSE = "K2 Vulnerability scanner response : %s";

    private static final String BASH_COMMAND = "bash";

    private static final String TMP_LOCALCVESERVICE_DIST_STARTUP_SH = "/tmp/localcveservice/dist/startup.sh";

    private static final String LOCALCVESERVICE_PATH = "localcveservice";

    public static final String KILL_PROCESS_TREE_COMMAND = "kill -9 -%s";
    public static final String KILLING_PROCESS_TREE_ROOTED_AT_S = "Killing process tree rooted at : %s";
    public static final String SETSID = "setsid";
    public static final String ZIP_FILE_DOWNLOADED_FAIL = "zip file downloaded fail.";
    public static final String ZIP_FILE_DOWNLOADED = "zip file downloaded.";

    private String nodeId;

    private boolean downloadTarBundle = false;

    private String kind;

    private String id;

    private boolean isEnvScan;
    final String bundleNameRegex = ICVEConstants.LOCALCVESERVICE_WIN_ZIP_REGEX;

    private OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

    public CVEServiceWindows(String nodeId, String kind, String id, boolean downloadTarBundle, boolean isEnvScan) {
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
            boolean downloaded = false;
            if (downloadTarBundle || StringUtils.equals(packageInfo.getLatestServiceVersion(), CVEScannerPool.getInstance().getPackageInfo().getLatestServiceVersion())) {
                downloaded = CVEComponentsService.downloadCVEPackage(packageInfo);
            }
            if (!downloaded) {
                return;
            }
            //Create untar Directory
            File extractedPackageDir = new File(packageParentDir, LOCALCVESERVICE_PATH);
            FileUtils.deleteQuietly(extractedPackageDir);
            if (!extractedPackageDir.exists()) {
                try {
                    extractedPackageDir.mkdirs();
                } catch (Throwable e) {
                    logger.log(LogLevel.ERROR, CANNOT_CREATE_DIRECTORY + extractedPackageDir, e,
                            CVEServiceWindows.class.getName());
                    return;
                }
            }

            AgentUtils.getInstance().unZipFile(CVEScannerPool.getInstance().getPackageInfo().getCvePackage(), extractedPackageDir);
            //TODO set permissions for extracted package if needed.
//            setAllPermissions(parentDirectory.getAbsolutePath());

            List<CVEScanner> scanDirs;
            if (isEnvScan) {
                scanDirs = CVEComponentsService.getLibScanDirs(packageParentDir);
            } else {
                scanDirs = CVEComponentsService.getAppScanDirs();
            }
            for (CVEScanner scanner : scanDirs) {
                File inputYaml = CVEComponentsService.createServiceYml(nodeId, scanner.getAppName(),
                        scanner.getAppSha256(), scanner.getDir(),
                        K2Instrumentator.APPLICATION_INFO_BEAN.getApplicationUUID(), scanner.getEnv(), kind, id, packageParentDir);
                //TODO windows ki maaya
                List<String> paramList = Arrays.asList(SETSID, BASH_COMMAND, TMP_LOCALCVESERVICE_DIST_STARTUP_SH,
                        inputYaml.getAbsolutePath());
                ProcessBuilder processBuilder = new ProcessBuilder(paramList);
                Process process = processBuilder.start();
                if (!process.waitFor(10, TimeUnit.MINUTES)) {
                    long pid = AgentUtils.getInstance().getProcessID(process);
                    if (pid > 1) {
                        logger.log(LogLevel.WARNING, String.format(KILLING_PROCESS_TREE_ROOTED_AT_S, pid), CVEServiceWindows.class.getName());
                        AgentUtils.getInstance().incrementCVEServiceFailCount();
                        Runtime.getRuntime().exec(String.format(KILL_PROCESS_TREE_COMMAND, pid));
                    }
                } else if (process.exitValue() != 0) {
                    AgentUtils.getInstance().incrementCVEServiceFailCount();
                }
                //Till here
                List<String> response = IOUtils.readLines(process.getInputStream(), StandardCharsets.UTF_8);
                logger.log(LogLevel.INFO,
                        String.format(K2_VULNERABILITY_SCANNER_RESPONSE, StringUtils.join(response, StringUtils.LF)),
                        CVEServiceWindows.class.getName());
                List<String> errResponse = IOUtils.readLines(process.getErrorStream(), StandardCharsets.UTF_8);
                logger.log(LogLevel.ERROR, String.format(K2_VULNERABILITY_SCANNER_RESPONSE_ERROR,
                        StringUtils.join(errResponse, StringUtils.LF)), CVEServiceWindows.class.getName());
                try {
                    FileUtils.forceDelete(inputYaml);
                } catch (Throwable e) {
                }
            }
            CVEComponentsService.deleteAllComponents(extractedPackageDir, packageParentDir);
        } catch (InterruptedException e) {
            logger.log(LogLevel.ERROR, ERROR_PROCESS_TERMINATED, e, CVEServiceWindows.class.getName());
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, ERROR, e, CVEServiceWindows.class.getName());
        }

    }


}
