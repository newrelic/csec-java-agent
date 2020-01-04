package com.k2cybersecurity.instrumentator.utils;

import java.util.Set;

import com.k2cybersecurity.instrumentator.K2Instrumentator;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;
import com.k2cybersecurity.intcodeagent.websocket.EventSendPool;

public class ApplicationInfoUtils {

	
	public static void updateServerInfo() {
		Set<DeployedApplication> deployedApplications = getAllDeployedApplications();
		Boolean resend = false;
		for (DeployedApplication deployedApplication : deployedApplications) {
			if (!K2Instrumentator.APPLICATION_INFO_BEAN.getServerInfo().getDeployedApplications().contains(deployedApplication)) {
				HashGenerator.updateShaAndSize(deployedApplication);
				K2Instrumentator.APPLICATION_INFO_BEAN.getServerInfo().getDeployedApplications().add(deployedApplication);
				resend = true;
			}
		}
		if (resend) {
			EventSendPool.getInstance().sendEvent(K2Instrumentator.APPLICATION_INFO_BEAN.toString());
		}
	}

	private static Set<DeployedApplication> getAllDeployedApplications() {
		// TODO Auto-generated method stub
		return null;
	}
	
	
}
