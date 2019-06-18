package com.k2cybersecurity.intcodeagent.logging;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.HOST_IP_PROPERTIES_FILE;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.IPSCHEDULEDTHREAD_;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.util.Collections;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.k2cybersecurity.intcodeagent.models.javaagent.JAHealthCheck;


public class IPScheduledThread {

	private static IPScheduledThread instance;
	private static Logger logger;
	
	private static ScheduledExecutorService ipScheduledService;

	private IPScheduledThread() {
		Runnable runnable = new Runnable() {
			public void run() {
				try (BufferedReader reader = new BufferedReader(new FileReader(HOST_IP_PROPERTIES_FILE))) {
					String hostip = reader.readLine();

					Socket socket =  EventThreadPool.getInstance().getSocket();
					ObjectOutputStream oos = EventThreadPool.getInstance().getObjectStream();
					try {
						// since tcp connection keep alive check is more than 2 hours
						// we send our custom object to check if connectino is still alive or not
						// this will be ignored by ic agent on the other side.
						synchronized (oos) {
							oos.writeUnshared(Collections.singletonList(new JAHealthCheck(LoggingInterceptor.JA_HEALTH_CHECK)));
						}
					    LoggingInterceptor.JA_HEALTH_CHECK.setEventDropCount(0);

					} catch (SocketException ex) {
						// if ack fails, socket needs to be properly closed as it is not done implicitly
						logger.error("Error in writing");
						LoggingInterceptor.closeSocket();
					} catch (NullPointerException ex) {
						logger.error("No reference to Socket's OutputStream");
					} catch (Exception e) {
						logger.error("Error while trying to verify connection: {}" ,e);
					}
					if (hostip == null || hostip.equals("")) {
						logger.debug("Host ip not found");
					} else if (!LoggingInterceptor.hostip.equals(hostip) || (socket == null)
							|| (!socket.isConnected()) || (socket.isClosed())) {
						LoggingInterceptor.connectSocket();
						LoggingInterceptor.getJarPath();
						logger.debug("K2-JavaAgent re-installed successfully.");
					} else {
						
					}
				} catch (Exception e) {
					logger.error("Error in IPScheduledThread : {}", e);
				}
			}
		};
		ipScheduledService = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
			private final AtomicInteger threadNumber = new AtomicInteger(1);
			
			@Override
			public Thread newThread(Runnable r) {
				return new Thread(Thread.currentThread().getThreadGroup(), r,
						IPSCHEDULEDTHREAD_ + threadNumber.getAndIncrement());
			}
		});
		ipScheduledService.scheduleAtFixedRate(runnable, 2, 1, TimeUnit.MINUTES);
	}

	public static IPScheduledThread getInstance() {
		try {
			if (instance == null)
				instance = new IPScheduledThread();
			return instance;
		} catch (Exception e) {
			logger.error("Error while starting: {}" ,e);
		}
		throw null;
	}
	
	public static void setLogger() {
		IPScheduledThread.logger = LogManager.getLogger(IPScheduledThread.class);
	}
}