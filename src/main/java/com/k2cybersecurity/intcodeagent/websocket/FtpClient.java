package com.k2cybersecurity.intcodeagent.websocket;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPConnectionClosedException;
import org.apache.commons.net.ftp.FTPReply;
import org.apache.commons.net.io.CopyStreamException;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.filelogging.LogWriter;

public class FtpClient {
	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

	private static FTPClient getClient() {
		FTPClient ftp = new FTPClient();
		/* connecting to FTP server */
		int retryFtp = 5;
		while (retryFtp-- > 0) {
			try {
				ftp.setRemoteVerificationEnabled(false);
				ftp.connect(K2Instrumentator.hostip, 54322);
				ftp.login("test", "test");
				int reply = ftp.getReplyCode();
				logger.log(LogLevel.DEBUG, "FTP server connection reply code : " + reply, WSClient.class.getName());
				if (FTPReply.isPositiveCompletion(reply)) {
					return ftp;
				} else {
					try {
						ftp.disconnect();
					} catch (IOException e) {
						logger.log(LogLevel.ERROR,
								"FTP server refused connection : " + K2Instrumentator.hostip + ":54322",
								WSClient.class.getName());
					}
				}
			} catch (IOException e) {
				logger.log(LogLevel.ERROR, "Error in connecting to FTP at " + K2Instrumentator.hostip + ":54322",
						WSClient.class.getName());
				return null;
			}
		}
		return ftp;
	}

	public static boolean sendLogFile(File file) {
		boolean result = false;
		FTPClient ftp = getClient();

		InputStream input = null;
		try {
			input = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			logger.log(LogLevel.ERROR, "log file not found " + file, WSClient.class.getName());
		}

		try {
			result = ftp.storeFile(file.getName(), input);
		} catch (FTPConnectionClosedException e) {
			logger.log(LogLevel.ERROR, "Connection closed by FTP server : " + e.getMessage(), WSClient.class.getName());
		} catch (CopyStreamException e) {
			logger.log(LogLevel.ERROR, "Exception in copying stream : " + e.getMessage(), WSClient.class.getName());
		} catch (IOException e) {
			logger.log(LogLevel.ERROR, "Exception in storing file to server : " + e, WSClient.class.getName());
			e.printStackTrace();
		}

		try {
			input.close();
			ftp.disconnect();
		} catch (IOException e) {
			logger.log(LogLevel.WARNING, "Exception in resource closing : " + e, WSClient.class.getName());
		}
		return result;
	}

	public static boolean sendBootstrapLogFile() {
		File blogFile = new File(LogWriter.getFileName());
		return FtpClient.sendLogFile(blogFile);
	}
}
