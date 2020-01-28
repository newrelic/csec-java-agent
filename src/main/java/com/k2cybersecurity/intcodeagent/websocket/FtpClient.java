package com.k2cybersecurity.intcodeagent.websocket;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPReply;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.filelogging.LogWriter;

public class FtpClient {
	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();

//	String BOOTSTRAP_APPLICATION_LOGS_REGEX = "\\/tmp\\/([1-9][0-9]*\\/)?k2_(java|node)_agent.*\\.log$";
//	String APPLICATION_LOGS_REGEX = "\\/tmp\\/([1-9][0-9]*\\/)?k2_(java|node)_agent.*\\.log\\.[1-9][0-9]*$";

	private static FTPClient getClient() {
		FTPClient ftp = new FTPClient();
		/* connecting to FTP server */
		int retryFtp = 5;
		while (retryFtp-- > 0) {
			try {
				ftp.connect(K2Instrumentator.hostip, 54322);
				ftp.login("test", "test");
				int reply = ftp.getReplyCode();
				System.out.println("Reply :" + reply);
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
		try (InputStream input = new FileInputStream(file)) {
			result = ftp.storeFile(file.getName(), input);
			logger.log(LogLevel.DEBUG, "File Upload for file " + file.getName() + "response : " + result, WSClient.class.getName());
		} catch (IOException e) {
			logger.log(LogLevel.ERROR, "log file not found " + file, WSClient.class.getName());
		}
		try {
			ftp.disconnect();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return result;
	}

	public static boolean sendBootstrapLogFile() {
		File blogFile = new File(LogWriter.getFileName());
		return FtpClient.sendLogFile(blogFile);
	}
}
