package com.k2cybersecurity.instrumentator.utils;

import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.CMD_LINE_DIR;
import static com.k2cybersecurity.intcodeagent.logging.IAgentConstants.PROC_DIR;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;

public class ApplicationInfoUtils {

	public static void updateServerInfo() {
		Set<DeployedApplication> deployedApplications = getAllDeployedApplications();
		Boolean resend = false;
		for (DeployedApplication deployedApplication : deployedApplications) {
			if (!K2Instrumentator.APPLICATION_INFO_BEAN.getServerInfo().getDeployedApplications()
					.contains(deployedApplication)) {
				HashGenerator.updateShaAndSize(deployedApplication);
				K2Instrumentator.APPLICATION_INFO_BEAN.getServerInfo().getDeployedApplications()
						.add(deployedApplication);
				resend = true;
			}
		}
		if (resend) {
			EventSendPool.getInstance().sendEvent(K2Instrumentator.APPLICATION_INFO_BEAN.toString());
		}
	}

	public static String getDefaultGetway() throws IOException {
		try {
			List<String> routes = IOUtils.readLines(new FileInputStream(new File(PROC_DIR + "self/route")));
			for(int i=1; i<routes.size(); i++) {
				String[] route = routes.get(i).split("\\s+");
				if(StringUtils.equals("0000000",route[1])) {
					return getDefaultGetway(route[2]);
				}
			}
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return StringUtils.EMPTY;
	}

	private static String getDefaultGetway(String hexGateway) {
		hexGateway = StringUtils.reverse(hexGateway);
		
		StringBuilder gateway = new StringBuilder();
		for(int i=0; i<hexGateway.length(); i+=2) {
			String hex = StringUtils.substring(hexGateway, i, i+2);
			gateway.append(Integer.parseInt(hex, 16));
			gateway.append(".");
		}
		return StringUtils.removeEnd(gateway.toString(), ".");
	}

	public static void main(String[] args) throws IOException {
		try {
			System.out.println(getDefaultGetway());
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private static Set<DeployedApplication> getAllDeployedApplications() {
		// TODO Auto-generated method stub
		return null;
	}

}
