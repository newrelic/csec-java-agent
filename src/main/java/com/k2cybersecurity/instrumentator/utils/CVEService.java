package com.k2cybersecurity.instrumentator.utils;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
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

public class CVEService {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private static final String YML_TEMPLATE = "# path to dependency check tool.\r\n"
			+ "dependencycheck.command: /usr/bin/sh /tmp/localcveservice/dist/dependency-check/bin/dependency-check.sh  -prettyPrint -f JSON\r\n"
			+ "# connecting back to k2agent.\r\n" + "k2agent.websocket: ws://%s:54321/\r\n" + "k2agent.nodeId: %s\r\n"
			+ "#----- following are file scan specific options\\r\n" + "k2agent.scan.mode: file\r\n"
			+ "k2agent.application: %s\r\n" + "k2agent.applicationUuid: %s\r\n" + "k2agent.applicationSha256: %s\r\n"
			+ "k2agent.scanPath: %s\r\n";

	public static void startCVEService(String nodeId) {
		File cveTar = new File("/tmp/localcveservice.tar");
		if (!cveTar.isFile()) {
			logger.log(LogLevel.WARNING, "CVE-Service Tar doesn't exists.", CVEService.class.getName());
		}

		Runnable runnable = new Runnable() {
			public void run() {
				try {
					boolean downlaoded = downloadCVEJar(cveTar, "/tmp/localcveservice");
					if (!downlaoded) {
						return;
					}
					for (CVEScanner scanner : getAllScanDirs()) {
						File inputYaml = createServiceYml("/tmp/localcveservice", nodeId, scanner.getAppName(),
								scanner.getAppSha256(), scanner.getDir(),
								K2Instrumentator.APPLICATION_INFO_BEAN.getApplicationUUID());
						List<String> paramList = Arrays.asList("bash", "/tmp/localcveservice/dist/startup.sh",
								inputYaml.getAbsolutePath());
						ProcessBuilder processBuilder = new ProcessBuilder(paramList);
						Process process = processBuilder.start();
						process.waitFor();
						List<String> response = IOUtils.readLines(process.getInputStream(), StandardCharsets.UTF_8);
						logger.log(LogLevel.INFO, String.format("K2 Vulnerability scanner response : %s",
								StringUtils.join(response, StringUtils.LF)), CVEService.class.getName());
						List<String> errResponse = IOUtils.readLines(process.getErrorStream(), StandardCharsets.UTF_8);
						logger.log(LogLevel.ERROR, String.format("K2 Vulnerability scanner response error : %s",
								StringUtils.join(errResponse, StringUtils.LF)), CVEService.class.getName());
						try {
							FileUtils.forceDelete(inputYaml);
						} catch (Exception e) {
						}
					}
//					deleteAllComponents(cveTar, "/tmp/localcveservice");
				} catch (IOException e) {
					logger.log(LogLevel.ERROR, "Error: {}", e, CVEService.class.getName());
				} catch (InterruptedException e) {
					logger.log(LogLevel.ERROR, "Error Process terminated: {}", e, CVEService.class.getName());
				}

			}
		};
		Thread thread = new Thread(runnable, "K2-local-cve-service");
		thread.start();
	}

	protected static void deleteAllComponents(File cveTar, String cveDir) {
		try {
			FileUtils.forceDelete(cveTar);
		} catch (IOException e) {
		}
		try {
			FileUtils.forceDelete(new File(cveDir));
		} catch (IOException e) {
		}
	}

	private static void setAllPermissions(String loc) {
		try {
			Runtime.getRuntime().exec(String.format("chmod a+rwx -R %s", loc)).waitFor();
		} catch (Exception e) {
		}
	}

	private static boolean downloadCVEJar(File cveTar, String outputDir) {
		boolean download = FtpClient.downloadFile(cveTar.getName(), cveTar.getAbsolutePath());
		if (download) {
			File parentDirectory = new File(outputDir);
			if (!parentDirectory.isDirectory()) {
				try {
					parentDirectory.mkdirs();
				} catch (Exception e) {
					logger.log(LogLevel.ERROR, "Cannot create directory : " + parentDirectory, e,
							CVEService.class.getName());
					return false;
				}
			}

			try (TarArchiveInputStream inputStream = new TarArchiveInputStream(new FileInputStream(cveTar))) {
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
						logger.log(LogLevel.ERROR, "Error : ", e, CVEService.class.getName());
					}
				}
				setAllPermissions(parentDirectory.getAbsolutePath());
				return true;
			} catch (Exception e) {
				logger.log(LogLevel.ERROR, "Error : ", e, CVEService.class.getName());
			}
		} else {
			logger.log(LogLevel.ERROR, "Unable to download Local CVE Service tar from IC", CVEService.class.getName());
		}
		return false;

	}

	protected static File createServiceYml(String cveServicePath, String nodeId, String appName, String appSha256,
			String scanPath, String applicationUUID) throws IOException {
		String yaml = String.format(YML_TEMPLATE, K2Instrumentator.hostip, nodeId, appName, applicationUUID, appSha256,
				scanPath);
		File yml = new File("/tmp", "service-input.yml");
		logger.log(LogLevel.INFO, "input yml : " + yaml, CVEService.class.getName());
		FileUtils.write(yml, yaml, StandardCharsets.UTF_8);
		return yml;
	}

	protected static List<CVEScanner> getAllScanDirs() {
		List<CVEScanner> scanners = new ArrayList<>();
		if (!K2Instrumentator.APPLICATION_INFO_BEAN.getLibraryPath().isEmpty()) {
			for (String path : K2Instrumentator.APPLICATION_INFO_BEAN.getLibraryPath()) {
				if (StringUtils.endsWith(path, ".jar")) {
					scanners.add(new CVEScanner(K2Instrumentator.APPLICATION_INFO_BEAN.getBinaryName(),
							K2Instrumentator.APPLICATION_INFO_BEAN.getSha256(), path));
				}
			}
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

}
