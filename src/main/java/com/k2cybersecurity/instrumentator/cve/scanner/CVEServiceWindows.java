package com.k2cybersecurity.instrumentator.cve.scanner;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.os.OSVariables;
import com.k2cybersecurity.instrumentator.os.OsVariablesInstance;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.NameFileFilter;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEPackageInfo;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEScanner;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.nio.charset.Charset;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class CVEServiceWindows implements Runnable {

    private static final String CANNOT_CREATE_DIRECTORY = "Cannot create directory : ";

    private static final String ERROR_PROCESS_TERMINATED = "Error Process terminated: {}";

    private static final String ERROR = "Error: {}";

    private static final String K2_VULNERABILITY_SCANNER_RESPONSE_ERROR = "K2 Vulnerability scanner response error : %s";

    private static final String K2_VULNERABILITY_SCANNER_RESPONSE = "K2 Vulnerability scanner response : %s";

    private static final String LOCALCVESERVICE_PATH = "localcveservice";

    public static final String KILL_PROCESS_TREE_COMMAND = "kill -9 -%s";
    public static final String KILLING_PROCESS_TREE_ROOTED_AT_S = "Killing process tree rooted at : %s";
    public static final String SETSID = "setsid";
    public static final String ZIP_FILE_DOWNLOADED_FAIL = "zip file downloaded fail.";
    public static final String ZIP_FILE_DOWNLOADED = "zip file downloaded.";
    public static final String POWERSHELL_EXE = "powershell.exe";
    public static final String K_2_DEPENDENCY_CHECK_PATH = "\\K2\\dependency-check.ps1";
    public static final String K_2_STARTUP_SCRIPT = "K2\\startup.ps1";

    private String nodeId;

    private CVEPackageInfo packageInfo;

    private String kind;

    private String id;

    private boolean isEnvScan;
    final String bundleNameRegex = ICVEConstants.LOCALCVESERVICE_WIN_ZIP_REGEX;

    private OSVariables osVariables = OsVariablesInstance.getInstance().getOsVariables();

    public CVEServiceWindows(String nodeId, String kind, String id, CVEPackageInfo packageInfo, boolean isEnvScan) {
        this.nodeId = nodeId;
        this.kind = kind;
        this.id = id;
        this.packageInfo = packageInfo;
        this.isEnvScan = isEnvScan;
    }

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

    @Override
    public void run() {
        try {
            String packageParentDir = osVariables.getCvePackageBaseDir();
            logger.log(LogLevel.DEBUG, String.format(ICVEConstants.PACKAGE_INFO_LOGGER, packageInfo.toString(), CVEScannerPool.getInstance().getPackageInfo()), CVEServiceWindows.class.getName());
            if (CVEScannerPool.getInstance().getPackageInfo() == null || !CVEScannerPool.getInstance().getPackageInfo().getCvePackage().exists() || !StringUtils.equals(packageInfo.getLatestServiceVersion(), CVEScannerPool.getInstance().getPackageInfo().getLatestServiceVersion())) {
                Collection<File> cvePackages = FileUtils.listFiles(new File(osVariables.getCvePackageBaseDir()), new NameFileFilter(ICVEConstants.LOCALCVESERVICE), null);
                logger.log(LogLevel.DEBUG, ICVEConstants.FILES_TO_DELETE + cvePackages, CVEServiceWindows.class.getName());
                cvePackages.forEach(FileUtils::deleteQuietly);
                CVEComponentsService.downloadCVEPackage(packageInfo);
            }
            if (CVEScannerPool.getInstance().getPackageInfo() == null || !CVEScannerPool.getInstance().getPackageInfo().getCvePackage().exists()) {
                return;
            }
            logger.log(LogLevel.DEBUG, ICVEConstants.CVE_PACKAGE_DOWNLOADED, CVEServiceWindows.class.getName());
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
            FileUtils.deleteQuietly(CVEScannerPool.getInstance().getPackageInfo().getCvePackage());
            //TODO set permissions for extracted package if needed.
//            setAllPermissions(parentDirectory.getAbsolutePath());

            logger.log(LogLevel.DEBUG, ICVEConstants.CVE_PACKAGE_EXTRACTION_COMPLETED, CVEServiceWindows.class.getName());

            StringBuilder dcCommand = new StringBuilder(POWERSHELL_EXE);
            dcCommand.append(StringUtils.SPACE);
            dcCommand.append(extractedPackageDir.getAbsolutePath());
            dcCommand.append(K_2_DEPENDENCY_CHECK_PATH);

            String startupScriptPath = new File(extractedPackageDir.getAbsolutePath(), K_2_STARTUP_SCRIPT).getAbsolutePath();

            List<CVEScanner> scanDirs;
            if (isEnvScan) {
                scanDirs = CVEComponentsService.getLibScanDirs();
            } else {
                scanDirs = CVEComponentsService.getAppScanDirs();
            }
            for (CVEScanner scanner : scanDirs) {
                File inputYaml = CVEComponentsService.createServiceYml(dcCommand.toString(), nodeId, scanner.getAppName(),
                        scanner.getAppSha256(), scanner.getDir(),
                        K2Instrumentator.APPLICATION_INFO_BEAN.getApplicationUUID(), scanner.getEnv(), kind, id, extractedPackageDir.getAbsolutePath());
                List<String> paramList = Arrays.asList(POWERSHELL_EXE, startupScriptPath,
                        inputYaml.getAbsolutePath());
                ProcessBuilder processBuilder = new ProcessBuilder(paramList);
                File dcout = Paths.get(extractedPackageDir.getAbsolutePath(), ICVEConstants.DC_TRIGGER_LOG).toFile();
                processBuilder.redirectErrorStream(true);
                processBuilder.redirectOutput(dcout);
                Process process = processBuilder.start();
                if (!process.waitFor(10, TimeUnit.MINUTES)) {
                    //TODO windows ki maaya
                    long pid = AgentUtils.getInstance().getProcessID(process);
                    if (pid > 1) {
                        logger.log(LogLevel.WARN, String.format(KILLING_PROCESS_TREE_ROOTED_AT_S, pid), CVEServiceWindows.class.getName());
                        AgentUtils.getInstance().incrementCVEServiceFailCount();
//                        Runtime.getRuntime().exec(String.format(KILL_PROCESS_TREE_COMMAND, pid));
                    }
                } else if (process.exitValue() != 0) {
                    AgentUtils.getInstance().incrementCVEServiceFailCount();
                }
                //Till here

                logger.log(LogLevel.INFO,
                        String.format(K2_VULNERABILITY_SCANNER_RESPONSE, FileUtils.readFileToString(Paths.get(extractedPackageDir.getAbsolutePath(), ICVEConstants.DC_TRIGGER_LOG).toFile(), Charset.defaultCharset())),
                        CVEServiceWindows.class.getName());
                try {
                    FileUtils.forceDelete(inputYaml);
                } catch (Throwable e) {
                }
            }
            CVEComponentsService.deleteAllComponents(osVariables.getCvePackageBaseDir());
            logger.log(LogLevel.DEBUG, ICVEConstants.CVE_PACKAGE_DELETED, CVEServiceWindows.class.getName());
            return;
        } catch (InterruptedException e) {
            logger.log(LogLevel.ERROR, ERROR_PROCESS_TERMINATED, e, CVEServiceWindows.class.getName());
        } catch (Throwable e) {
            logger.log(LogLevel.ERROR, ERROR, e, CVEServiceWindows.class.getName());
        }
        AgentUtils.getInstance().setCveEnvScanCompleted(false);

    }


}
