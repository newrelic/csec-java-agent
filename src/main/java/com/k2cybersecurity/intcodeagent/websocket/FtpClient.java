package com.k2cybersecurity.intcodeagent.websocket;

import com.k2cybersecurity.instrumentator.utils.AgentUtils;
import com.k2cybersecurity.instrumentator.utils.CollectorConfigurationUtils;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.filelogging.LogWriter;
import org.apache.commons.net.ftp.FTP;
import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPConnectionClosedException;
import org.apache.commons.net.ftp.FTPReply;
import org.apache.commons.net.io.CopyStreamException;

import java.io.*;

public class FtpClient {
	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private static FTPClient getClient() {
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

	public static boolean sendLogFile(File file) {
		boolean result = false;
		FTPClient ftp = getClient();
		if (ftp == null) {
			return false;
		}
		InputStream input = null;
		try {
			input = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			logger.log(LogLevel.ERROR, "log file not found " + file, FtpClient.class.getName());
		}

		try {
			result = ftp.storeFile(file.getName(), input);
		} catch (FTPConnectionClosedException e) {
			logger.log(LogLevel.ERROR, "Connection closed by FTP server : ", e, FtpClient.class.getName());
		} catch (CopyStreamException e) {
			logger.log(LogLevel.ERROR, "Exception in copying stream : ", e, FtpClient.class.getName());
		} catch (IOException e) {
			logger.log(LogLevel.ERROR, "Exception in storing file to server : " + e, FtpClient.class.getName());
		}

		try {
			input.close();
			ftp.disconnect();
		} catch (IOException e) {
		}
		return result;
	}

	public static boolean downloadFile(String fileName, String outputFile) {
		FTPClient ftp = getClient();
		if (ftp == null) {
			return false;
		}
		try (FileOutputStream fileOutputStream = new FileOutputStream(new File(outputFile))) {
			return ftp.retrieveFile(fileName, fileOutputStream);
		} catch (IOException e) {
			logger.log(LogLevel.WARNING, "Error : ", e, FtpClient.class.getName());
		}
		try {
			ftp.disconnect();
		} catch (IOException e) {}
		return false;
	}

	public static boolean sendBootstrapLogFile() {
		File blogFile = new File(LogWriter.getFileName());
		return FtpClient.sendLogFile(blogFile);
	}
}
