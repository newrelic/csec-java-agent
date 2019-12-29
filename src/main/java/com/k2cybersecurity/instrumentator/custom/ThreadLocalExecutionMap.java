package com.k2cybersecurity.instrumentator.custom;

import com.k2cybersecurity.intcodeagent.models.javaagent.AgentMetaData;
import com.k2cybersecurity.intcodeagent.models.javaagent.HttpRequestBean;
import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;

public class ThreadLocalExecutionMap {

    private HttpRequestBean httpRequestBean;

    private AgentMetaData metaData;

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
}
