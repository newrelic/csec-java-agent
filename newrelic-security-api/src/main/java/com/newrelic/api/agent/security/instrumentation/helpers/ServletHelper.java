package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.APIRecordStatus;
import com.newrelic.api.agent.security.schema.K2RequestIdentifier;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;

import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;

public class ServletHelper {
    public static final String SEPARATOR_SEMICOLON = ":K2:";
    public static final String K2_HOME_TMP_CONST = "{{K2_HOME_TMP}}";

    public static K2RequestIdentifier parseFuzzRequestIdentifierHeader(String requestHeaderVal) {
        K2RequestIdentifier k2RequestIdentifierInstance = new K2RequestIdentifier();
        if (StringUtils.isBlank(requestHeaderVal)) {
            k2RequestIdentifierInstance.setRaw(StringUtils.EMPTY);
            return k2RequestIdentifierInstance;
        }
        if (StringUtils.isNotBlank(requestHeaderVal)) {
            k2RequestIdentifierInstance.setRaw(requestHeaderVal);
            if (!(NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getEnabled()
                    && NewRelicSecurity.getAgent().getCurrentPolicy().getVulnerabilityScan().getIastScan().getEnabled())) {
                return k2RequestIdentifierInstance;
            }
            String[] data = StringUtils.splitByWholeSeparatorWorker(requestHeaderVal, SEPARATOR_SEMICOLON, -1, false);

            if (data.length >= 5) {
                k2RequestIdentifierInstance.setApiRecordId(data[0].trim());
                k2RequestIdentifierInstance.setRefId(data[1].trim());
                k2RequestIdentifierInstance.setRefValue(data[2].trim());
                k2RequestIdentifierInstance.setNextStage(APIRecordStatus.valueOf(data[3].trim()));
                k2RequestIdentifierInstance.setRecordIndex(Integer.parseInt(data[4].trim()));
                k2RequestIdentifierInstance.setK2Request(true);
                if (data.length >= 6 && StringUtils.isNotBlank(data[5])) {
                    k2RequestIdentifierInstance.setRefKey(data[5].trim());
                }
                if (data.length >= 7) {
                    for (int i = 6; i < data.length; i++) {
                        String tmpFile = data[i].trim();
                        k2RequestIdentifierInstance.getTempFiles().add(tmpFile);
                        try {
                            tmpFile = StringUtils.replace(tmpFile, K2_HOME_TMP_CONST,
                                    NewRelicSecurity.getAgent().getAgentTempDir());
                            File fileToCreate = new File(tmpFile);
                            if (fileToCreate.getParentFile() != null) {
                                fileToCreate.getParentFile().mkdirs();
                            }
                            fileToCreate.getParentFile().mkdirs();
                            Files.createFile(fileToCreate.toPath());
                        } catch (Throwable ignored) {
                        }
                    }
                }
            }
        }
        return k2RequestIdentifierInstance;
    }

    public static void registerUserLevelCode(String frameworkName) {
        try {
            if (!NewRelicSecurity.isHookProcessingActive() || NewRelicSecurity.getAgent().getSecurityMetaData().getRequest().isEmpty()
            ) {
                return;
            }
            SecurityMetaData securityMetaData = NewRelicSecurity.getAgent().getSecurityMetaData();
            if (!securityMetaData.getMetaData().isUserLevelServiceMethodEncountered(frameworkName)) {
                securityMetaData.getMetaData().setUserLevelServiceMethodEncountered(true);
                StackTraceElement[] trace = Thread.currentThread().getStackTrace();
                securityMetaData.getMetaData().setServiceTrace(Arrays.copyOfRange(trace, 1, trace.length));
            }
        } catch (Throwable ignored) {
        }
    }
}
