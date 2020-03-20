package com.k2cybersecurity.instrumentator.cve.scanner;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CVEService implements Runnable {

	private static final String JAR_EXT = ".jar";

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

	private String nodeId;

	public CVEService(String nodeId) {
		this.nodeId = nodeId;
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
			if (!cveTar.isFile()) {
				logger.log(LogLevel.WARNING, CVE_SERVICE_TAR_DOESN_T_EXISTS, CVEService.class.getName());
			}
			cveTar.delete();
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
				process.waitFor();
				List<String> response = IOUtils.readLines(process.getInputStream(), StandardCharsets.UTF_8);
				logger.log(LogLevel.INFO,
						String.format(K2_VULNERABILITY_SCANNER_RESPONSE, StringUtils.join(response, StringUtils.LF)),
						CVEService.class.getName());
				List<String> errResponse = IOUtils.readLines(process.getErrorStream(), StandardCharsets.UTF_8);
				logger.log(LogLevel.ERROR, String.format(K2_VULNERABILITY_SCANNER_RESPONSE_ERROR,
						StringUtils.join(errResponse, StringUtils.LF)), CVEService.class.getName());
				try {
					FileUtils.forceDelete(inputYaml);
				} catch (Exception e) {
				}
			}
			deleteAllComponents(cveTar, TMP_LOCALCVESERVICE_PATH);
		} catch (InterruptedException e) {
			logger.log(LogLevel.ERROR, ERROR_PROCESS_TERMINATED, e, CVEService.class.getName());
		} catch (Exception e) {
			logger.log(LogLevel.ERROR, ERROR, e, CVEService.class.getName());
		}

	}

	protected void deleteAllComponents(File cveTar, String cveDir) {
		try {
			FileUtils.forceDelete(cveTar);
		} catch (IOException e) {
		}
		try {
			FileUtils.forceDelete(new File(cveDir));
		} catch (IOException e) {
		}
		
//		try {
//			FileUtils.forceDelete(new File("/tmp/libs-"+ K2Instrumentator.APPLICATION_UUID));
//		} catch (IOException e) {
//		}
	}

	private void setAllPermissions(String loc) {
		try {
			Runtime.getRuntime().exec(String.format(CHMOD_A_RWX_R_S, loc)).waitFor();
		} catch (Exception e) {
		}
	}

	private boolean downloadCVEJar(File cveTar, String outputDir) {
		boolean download = FtpClient.downloadFile(cveTar.getName(), cveTar.getAbsolutePath());
		if (download) {
			File parentDirectory = new File(outputDir);
			if (!parentDirectory.isDirectory()) {
				try {
					parentDirectory.mkdirs();
				} catch (Exception e) {
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
					} catch (Exception e) {
						logger.log(LogLevel.ERROR, ERROR_LOG, e, CVEService.class.getName());
					}
				}
				setAllPermissions(parentDirectory.getAbsolutePath());
				return true;
			} catch (Exception e) {
				logger.log(LogLevel.ERROR, ERROR_LOG, e, CVEService.class.getName());
			}
		} else {
			logger.log(LogLevel.ERROR, "Unable to download Local CVE Service tar from IC", CVEService.class.getName());
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
		List<String> libPaths = new ArrayList<>();
		if (!K2Instrumentator.APPLICATION_INFO_BEAN.getLibraryPath().isEmpty()) {
			for (String path : K2Instrumentator.APPLICATION_INFO_BEAN.getLibraryPath()) {
				if (StringUtils.endsWith(path, JAR_EXT)) {
					libPaths.add(path);
				} else if (new File(path).isDirectory()) {
					FileUtils.listFiles(new File(path), new String[] { JAR_EXT }, true)
							.forEach(jarFile -> libPaths.add(jarFile.getAbsolutePath()));
				}
			}
		}
		List<CVEScanner> scanners = new ArrayList<>();
		if (!libPaths.isEmpty()) {
			CVEScanner cveScanner = createLibTmpDir(libPaths, K2Instrumentator.APPLICATION_INFO_BEAN.getBinaryName(),
					K2Instrumentator.APPLICATION_INFO_BEAN.getApplicationUUID());
			scanners.add(cveScanner);
		}

		if (K2Instrumentator.APPLICATION_INFO_BEAN.getServerInfo().getDeployedApplications() != null) {
			for (Object obj : K2Instrumentator.APPLICATION_INFO_BEAN.getServerInfo().getDeployedApplications()) {
				DeployedApplication deployedApplication = (DeployedApplication) obj;
				scanners.add(new CVEScanner(deployedApplication.getAppName(), deployedApplication.getSha256(),
						deployedApplication.getDeployedPath()));
			}
		}
		return scanners;
	}

	private CVEScanner createLibTmpDir(List<String> libPaths, String binaryName, String applicationUUID) {
		File directory = new File("/tmp/libs-", applicationUUID);
		try {
			FileUtils.forceMkdir(directory);
			for (String path : libPaths) {
				logger.log(LogLevel.DEBUG, "Add jar : "+path, CVEService.class.getName());
				FileUtils.copyFileToDirectory(new File(path), directory, true);
			}
			return new CVEScanner(binaryName + " Env Libs " + applicationUUID,
					HashGenerator.getSHA256ForDirectory(directory.getAbsolutePath()), directory.getAbsolutePath());
		} catch (IOException e) {
		}
		return null;
	}
}
