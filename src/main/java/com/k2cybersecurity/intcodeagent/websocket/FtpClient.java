package com.k2cybersecurity.intcodeagent.websocket;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.CollectorConfigurationUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.filelogging.LogWriter;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.net.ftp.*;
import org.apache.commons.net.io.CopyStreamException;

import java.io.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

public class FtpClient {
	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	/**
	 * Remember to disconnect connection after use of the client. (Caller's responsibility)
	 */
	public static FTPClient getClient() {
		FTPClient ftp = new FTPClient();
		/* connecting to FTP server */
		int retryFtp = 5;
		while (retryFtp-- > 0) {
			try {
				ftp.setRemoteVerificationEnabled(false);


				if (AgentUtils.getInstance().getInitMsg() != null) {
					ftp.connect(CollectorConfigurationUtils.getInstance().getCollectorConfig().getK2ServiceInfo().getServiceEndpointAddress(), AgentUtils.getInstance().getInitMsg().getStartupProperties().getFtpProperties().getPort());
					ftp.login(AgentUtils.getInstance().getInitMsg().getStartupProperties().getFtpProperties().getUsername(),
							AgentUtils.getInstance().getInitMsg().getStartupProperties().getFtpProperties().getPassword());
				} else {
					logger.log(LogLevel.WARNING, "Collector has not been initialised yet. Cannot perform operation", FtpClient.class.getName());
					return null;
				}


				int reply = ftp.getReplyCode();
				logger.log(LogLevel.DEBUG, "FTP server connection reply code : " + reply, FtpClient.class.getName());
				ftp.setFileType(FTP.BINARY_FILE_TYPE);
				ftp.setDataTimeout(1000);
				if (FTPReply.isPositiveCompletion(reply)) {
					return ftp;
				} else {
					try {
						ftp.disconnect();
					} catch (IOException e) {
						logger.log(LogLevel.ERROR,
								"FTP server refused connection : " + CollectorConfigurationUtils.getInstance().getCollectorConfig().getK2ServiceInfo().getServiceEndpointAddress() + ":54322",
								FTPClient.class.getName());
					}
				}
			} catch (IOException e) {
				logger.log(LogLevel.ERROR, "Error in connecting to FTP at " + CollectorConfigurationUtils.getInstance().getCollectorConfig().getK2ServiceInfo().getServiceEndpointAddress() + ":54322", e,
						FTPClient.class.getName());
				return null;
			}
		}
		return ftp;
	}

	public static boolean sendLogFile(File file, String hostDir) {
		boolean result = false;
		FTPClient ftp = getClient();
		InputStream input = null;
		try {
			if (ftp == null) {
				return false;
			}
			try {
				input = new FileInputStream(file);
			} catch (FileNotFoundException e) {
				logger.log(LogLevel.ERROR, "log file not found " + file, FtpClient.class.getName());
			}

			try {
				result = ftp.storeFile(StringUtils.join(hostDir, file.getName()), input);
			} catch (FTPConnectionClosedException e) {
				logger.log(LogLevel.ERROR, "Connection closed by FTP server : ", e, FtpClient.class.getName());
			} catch (CopyStreamException e) {
				logger.log(LogLevel.ERROR, "Exception in copying stream : ", e, FtpClient.class.getName());
			} catch (IOException e) {
				logger.log(LogLevel.ERROR, "Exception in storing file to server : " + e, FtpClient.class.getName());
			}
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (Exception e) {
				}
			}
			if (ftp != null) {
				try {
					ftp.disconnect();
				} catch (Exception e) {
				}
			}
		}
		return result;
	}

	public static boolean downloadFile(FTPClient ftp, String fileName, String outputFile) {
		if (ftp == null) {
			return false;
		}
		try (FileOutputStream fileOutputStream = new FileOutputStream(new File(outputFile))) {
			return ftp.retrieveFile(fileName, fileOutputStream);
		} catch (IOException e) {
			logger.log(LogLevel.WARNING, "Error : ", e, FtpClient.class.getName());
		}
		return false;
	}

	public static String logUploadDir() {
		StringBuilder hostDir = new StringBuilder("logs");
		hostDir.append(File.separator);
		hostDir.append(CollectorConfigurationUtils.getInstance().getCollectorConfig().getCustomerInfo().getCustomerId());
		hostDir.append(File.separator);
		hostDir.append("application-logs");
		hostDir.append(File.separator);
		hostDir.append(K2Instrumentator.APPLICATION_UUID);
		hostDir.append(File.separator);
		return hostDir.toString();
	}

	public static boolean sendBootstrapLogFile() {
		File blogFile = new File(LogWriter.getFileName());
		return FtpClient.sendLogFile(blogFile, logUploadDir());
	}

	public static List<String> listAllFiles(FTPClient ftp, String regex) {
		try {
			if (ftp == null) {
				return Collections.emptyList();
			}
			FTPFile[] files = ftp.listFiles();
			List<String> allFiles = new ArrayList<>();
			Pattern pattern = Pattern.compile(regex);
			for (FTPFile file : files) {
				logger.log(LogLevel.INFO, "FTP File listing  : " + file.toString(), FtpClient.class.getName());
				if (file.isFile() && pattern.matcher(file.getName()).matches()) {
					allFiles.add(file.getName());
				}
			}
			return allFiles;
		} catch (IOException e) {
			logger.log(LogLevel.ERROR, "list files via ftp failed : ", e, FtpClient.class.getName());
		}
		return Collections.emptyList();
	}
}
