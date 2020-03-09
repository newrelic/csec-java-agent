package com.k2cybersecurity.instrumentator.utils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;

public class CVEService {

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private static final String YML_TEMPLATE = "k2agent.customerId: %s\n" + "k2agent.nodeId: %s\n"
			+ "k2agent.application: %s\n" + "k2agent.applicationSha256: %s\n" + "k2agent.scanPath: %s";

	public static void startCVEService(String customerId, String nodeId, String appName, String appSha256, String dir) {
		File cveJar = new File("/tmp/localcveservice-1.0-SNAPSHOT.jar");
		if (!cveJar.isFile()) {
			logger.log(LogLevel.WARNING, "CVE-Service JAR doesn't exists.", CVEService.class.getName());
		}else {
			try(FileOutputStream fOutputStream = new FileOutputStream(cveJar)) {
				InputStream cveJarStream = CVEService.class.getClassLoader()
						.getResourceAsStream("localcveservice-1.0-SNAPSHOT.jar");
				FileUtils.writeByteArrayToFile(cveJar, IOUtils.readFully(cveJarStream, cveJarStream.available()));
			} catch (IOException e) {
				logger.log(LogLevel.ERROR, "Error: {}", e, CVEService.class.getName());
				return;
			}
		}

		Runnable runnable = new Runnable() {
			public void run() {
				try {
					File inputYaml = createServiceYml(customerId, nodeId, appName, appSha256, dir);
					ProcessBuilder processBuilder = new ProcessBuilder(
							"java -Xms1G -Xmx1G -XX:+UseG1GC -XX:MaxGCPauseMillis=20 -jar " + cveJar.getAbsolutePath()
									+ " " + inputYaml.getAbsolutePath() + "");
					Process process = processBuilder.start();
					process.waitFor();
					inputYaml.delete();
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

	protected static File createServiceYml(String customerId, String nodeId, String appName, String appSha256, String scanPath)
			throws IOException {
		String yaml = String.format(YML_TEMPLATE, customerId, nodeId, appName, appSha256, scanPath);
		File yml = new File("/tmp", "service-input.yml");
		FileUtils.write(yml, yaml, StandardCharsets.UTF_8);
		return yml;
	}

}
