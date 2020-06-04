/**
 * DeployedApplication.java
 * <p>
 * Copyright (C) 2017 - k2 Cyber Security, Inc. All rights reserved.
 * <p>
 * This software is proprietary information of k2 Cyber Security, Inc and
 * constitutes valuable trade secrets of k2 Cyber Security, Inc. You shall
 * not disclose this information and shall use it only in accordance with the
 * terms of License.
 * <p>
 * K2 CYBER SECURITY, INC MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE
 * SUITABILITY OF THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT. K2 CYBER SECURITY, INC SHALL
 * NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING,
 * MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.
 * <p>
 * "K2 Cyber Security, Inc"
 */
package com.k2cybersecurity.intcodeagent.logging;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

/**
 * DeployedApplication model contains fields to identify all deployed
 * application inside a server.
 *
 * @author Team AppPerfect
 * @version 1.0
 */
public class DeployedApplication {

	public static final String FORWARD_SLASH = "/";

	public static final String UNDERSCORE = "_";

	/** Application deployed path. */
	private String deployedPath;

	/** Application name. */
	private String appName;

	/** sha 256 of application. */
	private String sha256;

	/** Size of application. */
	private String size;

	private String contextPath;

	private Integer port = -1;

	private boolean isEmbedded = false;

	public DeployedApplication() {
	}

	/**
	 * Gets the deployed path.
	 *
	 * @return the deployedPath
	 */
	public String getDeployedPath() {
		return deployedPath;
	}

	/**
	 * Sets the deployed path.
	 *
	 * @param deployedPath
	 *            the deployedPath to set
	 */
	public void setDeployedPath(String deployedPath) {
		if (StringUtils.isBlank(deployedPath)) {
			this.deployedPath = StringUtils.EMPTY;
		} else {
			this.deployedPath = deployedPath;
		}
	}

	public boolean isEmbedded() {
		return isEmbedded;
	}

	public void setEmbedded(boolean embedded) {
		isEmbedded = embedded;
	}

	/**
	 * Gets the app name.
	 *
	 * @return the appName
	 */
	public String getAppName() {
		return appName;
	}

	/**
	 * Sets the app name.
	 *
	 * @param appName
	 *            the appName to set
	 */
	public void setAppName(String appName) {
		if (StringUtils.isBlank(appName) || StringUtils.equals(appName, FORWARD_SLASH) || StringUtils.equals(appName, UNDERSCORE)) {
			this.appName = "ROOT";
		} else {
			this.appName = appName;
		}
	}

	/**
	 * @return the sha256
	 */
	public String getSha256() {
		return sha256;
	}

	/**
	 * @param sha256 the sha256 to set
	 */
	public void setSha256(String sha256) {
		this.sha256 = sha256;
	}

	/**
	 * @return the size
	 */
	public String getSize() {
		return size;
	}

	/**
	 * @param size the size to set
	 */
	public void setSize(String size) {
		this.size = size;
	}

	@Override public String toString() {
		return JsonConverter.toJSON(this);
	}

	public String getContextPath() {
		return contextPath;
	}

	public void setContextPath(String contextPath) {
		if (StringUtils.isBlank(contextPath)) {
			this.contextPath = FORWARD_SLASH;
		} else {
			this.contextPath = contextPath;
		}
	}

	public Integer getPort() {
		return port;
	}

	public void setPort(Integer port) {
		if(port == null || port <= 0){
			return;
		}
		this.port = port;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((port == null) ? 0 : port.hashCode());
		result = prime * result + ((contextPath == null) ? 0 : contextPath.hashCode());

		return result;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		DeployedApplication that = (DeployedApplication) o;
		return port.equals(that.port) &&
				contextPath.equals(that.contextPath);
	}

	public boolean isEmpty() {
		return StringUtils.isAnyBlank(deployedPath, appName, contextPath) || port == -1;
	}
}
