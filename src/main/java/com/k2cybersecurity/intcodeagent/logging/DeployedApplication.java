/** 
 * DeployedApplication.java
 *
 * Copyright (C) 2017 - k2 Cyber Security, Inc. All rights reserved.
 *
 * This software is proprietary information of k2 Cyber Security, Inc and
 * constitutes valuable trade secrets of k2 Cyber Security, Inc. You shall
 * not disclose this information and shall use it only in accordance with the
 * terms of License.
 *
 * K2 CYBER SECURITY, INC MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE
 * SUITABILITY OF THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT. K2 CYBER SECURITY, INC SHALL
 * NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING,
 * MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.
 * 
 * "K2 Cyber Security, Inc"
 */
package com.k2cybersecurity.intcodeagent.logging;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

/**
 * DeployedApplication model contains fields to identify all deployed
 * application inside a server.
 *
 * @author Team AppPerfect
 * @version 1.0
 */
public class DeployedApplication {

	/** Application deployed path. */
	private String deployedPath;

	/** Application name. */
	private String appName;
	
	/** sha 256 of application. */
	private String sha256;

	/** Size of application. */
	private String size;

	/** Check if it is war. */
	private boolean isWar;

	/** Check if it is jar. */
	private boolean isJar;
	
	private boolean isEar;

	public DeployedApplication() {
	}

	public DeployedApplication(String deployedPath, String appName) {
		this.deployedPath = deployedPath;
		this.appName = appName;
	}

	/**
	 * @return the isWar
	 */
	public boolean isWar() {
		return isWar;
	}

	/**
	 * @param isWar
	 *            the isWar to set
	 */
	public void setWar(boolean isWar) {
		this.isWar = isWar;
	}

	/**
	 * @return the isJar
	 */
	public boolean isJar() {
		return isJar;
	}

	/**
	 * @param isJar
	 *            the isJar to set
	 */
	public void setJar(boolean isJar) {
		this.isJar = isJar;
	}

	/**
	 * @return the isEar
	 */
	public boolean isEar() {
		return isEar;
	}

	/**
	 * @param isEar the isEar to set
	 */
	public void setEar(boolean isEar) {
		this.isEar = isEar;
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
		this.deployedPath = deployedPath;
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
		this.appName = appName;
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


	@Override
	public String toString() {
		return JsonConverter.toJSON(this);
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((appName == null) ? 0 : appName.hashCode());
		result = prime * result + ((deployedPath == null) ? 0 : deployedPath.hashCode());
		return result;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		DeployedApplication other = (DeployedApplication) obj;
		if (appName == null) {
			if (other.appName != null)
				return false;
		} else if (!appName.equals(other.appName))
			return false;
		if (deployedPath == null) {
			if (other.deployedPath != null)
				return false;
		} else if (!deployedPath.equals(other.deployedPath))
			return false;
		return true;
	}

}
