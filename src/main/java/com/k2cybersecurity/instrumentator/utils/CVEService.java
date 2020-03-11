package com.k2cybersecurity.instrumentator.utils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.models.javaagent.CVEScanner;
import com.k2cybersecurity.intcodeagent.websocket.FtpClient;

public class CVEService {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private static final String YML_TEMPLATE = "k2agent.customerId: %s\n" + "k2agent.nodeId: %s\n"
			+ "k2agent.application: %s\n" + "k2agent.applicationSha256: %s\n"
			+ "k2agent.scanPath: %s\n k2agent.websocket: %s";

	public static void startCVEService(String customerId, String nodeId) {
		File cveJar = new File("/tmp/localcveservice-1.0-SNAPSHOT.jar");
		if (!cveJar.isFile()) {
			logger.log(LogLevel.WARNING, "CVE-Service JAR doesn't exists.", CVEService.class.getName());
		}

		boolean downlaoded = downloadCVEJar(cveJar);
		if (!downlaoded) {
			return;
		}

		Runnable runnable = new Runnable() {
			public void run() {
				try {
					for (CVEScanner scanner : getAllScanDirs()) {
						File inputYaml = createServiceYml(customerId, nodeId, scanner.getAppName(),
								scanner.getAppSha256(), scanner.getDir());
						ProcessBuilder processBuilder = new ProcessBuilder(
								K2Instrumentator.APPLICATION_INFO_BEAN.getBinaryPath()
										+ " -Xms1G -Xmx1G -XX:+UseG1GC -XX:MaxGCPauseMillis=20 -jar "
										+ cveJar.getAbsolutePath() + " " + inputYaml.getAbsolutePath() + "");
						Process process = processBuilder.start();
						process.waitFor();
						inputYaml.delete();
					}
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

	private static boolean downloadCVEJar(File cveJar) {
		return FtpClient.downloadFile(cveJar.getName(), cveJar.getAbsolutePath());
	}

	protected static File createServiceYml(String customerId, String nodeId, String appName, String appSha256,
			String scanPath) throws IOException {
		String yaml = String.format(YML_TEMPLATE, customerId, nodeId, appName, appSha256, scanPath,
				String.format("ws://%s:54321", K2Instrumentator.hostip));
		File yml = new File("/tmp", "service-input.yml");
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
