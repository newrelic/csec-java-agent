package com.newrelic.api.agent.security.schema.policy;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class SkipScan {
    private List<String> apis = new ArrayList<>();

    private List<Pattern> apiRoutes = new ArrayList<>();

    private SkipScanParameters parameters = new SkipScanParameters();

    private IastDetectionCategory iastDetectionCategory = new IastDetectionCategory();

    public SkipScan() {
    }

    public List<String> getApis() {
        return apis;
    }

    public void setApis(List<String> apis) {
        this.apis = apis;
        if(apis != null) {
            for (String api : apis) {
                apiRoutes.add(Pattern.compile(api));
            }
        }
    }

    public List<Pattern> getApiRoutes() {
        return apiRoutes;
    }

    public void setApiRoutes(List<Pattern> apiRoutes) {
        this.apiRoutes = apiRoutes;
    }

    public SkipScanParameters getParameters() {
        return parameters;
    }

    public void setParameters(SkipScanParameters parameters) {
        this.parameters = parameters;
    }

    public IastDetectionCategory getIastDetectionCategory() {
        return iastDetectionCategory;
    }

    public void setIastDetectionCategory(IastDetectionCategory iastDetectionCategory) {
        this.iastDetectionCategory = iastDetectionCategory;
    }
}
