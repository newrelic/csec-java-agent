/**
 * ServerInfo.java
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
package com.newrelic.agent.security.intcodeagent.logging;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;


/**
 * ServerInfo contains basic field representing a server and it's deployed application.
 *
 * @author Team AppPerfect
 * @version 1.0
 */
public class ServerInfo implements Serializable {

    /** Constant serialVersionUID. */
    private static final long serialVersionUID = -8782687910717135760L;

    /** name of server. */
    private String name;

    /** list of all {@link DeployedApplication}. */
    private Set<DeployedApplication> deployedApplications;

    public ServerInfo() {
        this.name = StringUtils.EMPTY;
        deployedApplications = new HashSet<>();
    }

    /**
     * Gets the name.
     *
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the name.
     *
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }


    /**
     * Gets the deployed applications.
     *
     * @return the deployedApplications
     */
    public Set<DeployedApplication> getDeployedApplications() {
        return deployedApplications;
    }

    /**
     * Sets the deployed applications.
     *
     * @param deployedApplications the deployedApplications to set
     */
    public void setDeployedApplications(Set<DeployedApplication> deployedApplications) {
        this.deployedApplications = deployedApplications;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }


}
