package com.k2cybersecurity.instrumentator.custom;

import com.k2cybersecurity.instrumentator.httpclient.FuzzCleanUpST;
import com.k2cybersecurity.intcodeagent.models.javaagent.AgentMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.FileIntegrityBean;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

import java.util.HashMap;
import java.util.Map;

public class ThreadLocalExecutionMap {

    private HttpRequestBean httpRequestBean;

    private AgentMetaData metaData;

    private Map<String, FileIntegrityBean> fileLocalMap;

    private String tracingHeaderValue;

    private static ThreadLocal<ThreadLocalExecutionMap> instance =
            new ThreadLocal<ThreadLocalExecutionMap>() {
                @Override
                protected ThreadLocalExecutionMap initialValue() {
                    return new ThreadLocalExecutionMap();
                }
            };

    private ThreadLocalExecutionMap() {
        httpRequestBean = new HttpRequestBean();
        metaData = new AgentMetaData();
        setFileLocalMap(new HashMap<String, FileIntegrityBean>());
    }

    public static ThreadLocalExecutionMap getInstance() {
        return instance.get();
    }

    /**
     * @return the httpRequestBean
     */
    public HttpRequestBean getHttpRequestBean() {
        return httpRequestBean;
    }

    /**
     * @param httpRequestBean the httpRequestBean to set
     */
    public void setHttpRequestBean(HttpRequestBean httpRequestBean) {
        this.httpRequestBean = httpRequestBean;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    public AgentMetaData getMetaData() {
        return metaData;
    }

    public void setMetaData(AgentMetaData metaData) {
        this.metaData = metaData;
    }

    /**
     * @return the fileLocalMap
     */
    public Map<String, FileIntegrityBean> getFileLocalMap() {
        return fileLocalMap;
    }

    /**
     * @param fileLocalMap the fileLocalMap to set
     */
    public void setFileLocalMap(Map<String, FileIntegrityBean> fileLocalMap) {
        this.fileLocalMap = fileLocalMap;
    }

    public String getTracingHeaderValue() {
        return tracingHeaderValue;
    }

    public void setTracingHeaderValue(String tracingHeaderValue) {
        this.tracingHeaderValue = tracingHeaderValue;
    }

    public void cleanUp() {
        if (httpRequestBean != null && httpRequestBean.getK2RequestIdentifierInstance() != null && httpRequestBean.getK2RequestIdentifierInstance().getTempFiles() != null) {
            FuzzCleanUpST.getInstance().scheduleCleanUp(httpRequestBean.getK2RequestIdentifierInstance().getTempFiles());
        }
        httpRequestBean = new HttpRequestBean();
        metaData = new AgentMetaData();
        fileLocalMap.clear();
    }

}
