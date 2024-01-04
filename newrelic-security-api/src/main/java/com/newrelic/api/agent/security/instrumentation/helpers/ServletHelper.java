package com.newrelic.api.agent.security.instrumentation.helpers;

import com.newrelic.api.agent.security.NewRelicSecurity;
import com.newrelic.api.agent.security.schema.APIRecordStatus;
import com.newrelic.api.agent.security.schema.K2RequestIdentifier;
import com.newrelic.api.agent.security.schema.SecurityMetaData;
import com.newrelic.api.agent.security.schema.StringUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class ServletHelper {
    public static final String SEPARATOR_SEMICOLON = ":IAST:";
    public static final String NR_CSEC_VALIDATOR_HOME_TMP = "{{NR_CSEC_VALIDATOR_HOME_TMP}}";

    public static final String CSEC_IAST_FUZZ_REQUEST_ID = "nr-csec-fuzz-request-id";

    public static final String CSEC_DISTRIBUTED_TRACING_HEADER = "NR-CSEC-TRACING-DATA";
    public static final String SERVLET_GET_IS_OPERATION_LOCK = "SERVLET_GET_IS_OPERATION_LOCK-";
    public static final String SERVLET_GET_READER_OPERATION_LOCK = "SERVLET_GET_READER_OPERATION_LOCK-";
    public static final String SERVLET_GET_OS_OPERATION_LOCK = "SERVLET_GET_OS_OPERATION_LOCK-";
    public static final String SERVLET_GET_WRITER_OPERATION_LOCK = "SERVLET_GET_WRITER_OPERATION_LOCK-";
    public static final String NR_SEC_HTTP_SESSION_ATTRIB_NAME = "NR-CSEC-HTTP-SESSION-";
    public static final String NR_SEC_HTTP_SERVLET_RESPONSE_ATTRIB_NAME = "NR-CSEC-HTTP-SERVLET-RESPONSE-";

    private static Set<String> filesToRemove = ConcurrentHashMap.newKeySet();
    private static final Set<String> unsupportedContentType = new HashSet<String>() {{
        add("application/zip");
        add("application/epub+zip");
        add("application/gzip");
        add("application/java-archive");
        add("application/msword");
        add("application/octet-stream");
        add("application/ogg");
        add("application/pdf");
        add("application/rtf");
        add("application/vnd.amazon.ebook");
        add("application/vnd.apple.installer+xml");
        add("application/vnd.ms-excel");
        add("application/vnd.ms-fontobject");
        add("application/vnd.ms-powerpoint");
        add("application/vnd.oasis.opendocument.presentation");
        add("application/vnd.oasis.opendocument.spreadsheet");
        add("application/vnd.oasis.opendocument.text");
        add("application/vnd.openxmlformats-officedocument.presentationml.presentation");
        add("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
        add("application/vnd.openxmlformats-officedocument.wordprocessingml.document");
        add("application/vnd.rar");
        add("application/vnd.visio");
        add("application/x-7z-compressed");
        add("application/x-abiword");
        add("application/x-bzip");
        add("application/x-bzip2");
        add("application/x-cdf");
        add("application/x-freearc");
        add("application/x-tar");
        add("text/calendar");
    }};

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
                            tmpFile = StringUtils.replace(tmpFile, NR_CSEC_VALIDATOR_HOME_TMP,
                                    NewRelicSecurity.getAgent().getAgentTempDir());
                            File fileToCreate = new File(tmpFile);
                            if (fileToCreate.getParentFile() != null) {

                                File parentFile = fileToCreate;
                                while(!parentFile.getParentFile().exists()){
                                    parentFile = parentFile.getParentFile();
                                }
                                filesToRemove.add(parentFile.getAbsolutePath());
                                fileToCreate.getParentFile().mkdirs();
                            }
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


    public static Set<String> getFilesToRemove() {
        return filesToRemove;
    }

    public static void tmpFileCleanUp(List<String> files){
        for (String file : files) {
            try {
                Files.deleteIfExists(Paths.get(file));
            } catch (IOException e) {
            }
        }
    }

    public static boolean isResponseContentTypeExcluded( String responseContentType) {
        if (StringUtils.isBlank(responseContentType)) {
            return false;
        }
        responseContentType =  responseContentType.toLowerCase();
        if(StringUtils.startsWithAny(responseContentType, "audio/", "video/", "image/", "font/")){
            return true;
        }
        return unsupportedContentType.contains(responseContentType);
    }
}
