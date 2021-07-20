package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.Set;

public class ScanComponentData extends AgentBasicInfo {

    private String applicationUUID;

    private Set<CVEComponent> envComponents;

    private Set<ApplicationScanComponentData> deployedApplications;

    public ScanComponentData() {
        super();
    }

    public ScanComponentData(String applicationUuid) {
        super();
        this.applicationUUID = applicationUuid;
    }

    /**
     * @return the applicationUUID
     */
    public String getApplicationUUID() {
        return applicationUUID;
    }

    /**
     * @param applicationUUID the applicationUUID to set
     */
    public void setApplicationUUID(String applicationUUID) {
        this.applicationUUID = applicationUUID;
    }


    /**
     * @return the envComponents
     */
    public Set<CVEComponent> getEnvComponents() {
        return envComponents;
    }

    /**
     * @param envComponents the envComponents to set
     */
    public void setEnvComponents(Set<CVEComponent> envComponents) {
        this.envComponents = envComponents;
    }

    /**
     * @return the deployedApplications
     */
    public Set<ApplicationScanComponentData> getDeployedApplications() {
        return deployedApplications;
    }

    /**
     * @param deployedApplications the deployedApplications to set
     */
    public void setDeployedApplications(Set<ApplicationScanComponentData> deployedApplications) {
        this.deployedApplications = deployedApplications;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }
}
