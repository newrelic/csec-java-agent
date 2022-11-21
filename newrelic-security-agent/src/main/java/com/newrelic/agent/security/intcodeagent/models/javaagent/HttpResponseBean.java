package com.newrelic.agent.security.intcodeagent.models.javaagent;

import com.newrelic.agent.security.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;

public class HttpResponseBean {

    private JSONObject headers;

    private String responseBody;

    private String decodedResponseBody;

    private String responseCharacterEncoding;

    private String responseContentType;

    public HttpResponseBean() {
        this.headers = new JSONObject();
        this.responseBody = StringUtils.EMPTY;
        this.decodedResponseBody = StringUtils.EMPTY;
        this.responseCharacterEncoding = StringUtils.EMPTY;
        this.responseContentType = StringUtils.EMPTY;
    }

    public HttpResponseBean(HttpResponseBean httpResponseBean) {
        this.headers = new JSONObject(httpResponseBean.getHeaders());
        this.responseBody = new String(httpResponseBean.responseBody.trim());
        this.decodedResponseBody = new String(httpResponseBean.decodedResponseBody.trim());
        this.responseCharacterEncoding = new String(httpResponseBean.responseCharacterEncoding.trim());
        this.responseContentType = new String(httpResponseBean.responseContentType.trim());
    }

    public JSONObject getHeaders() {
        return headers;
    }

    public void setHeaders(JSONObject headers) {
        this.headers = headers;
    }

    public String getResponseBody() {
        return this.responseBody;
    }

    @Override
    public String toString() {
        return JsonConverter.toJSON(this);
    }

    public void setResponseBody(String responseBody) {
        this.responseBody = responseBody;
    }

    public String getResponseCharacterEncoding() {
        return responseCharacterEncoding;
    }

    public void setResponseCharacterEncoding(String responseCharacterEncoding) {
        this.responseCharacterEncoding = responseCharacterEncoding;
    }

    public String getResponseContentType() {
        return responseContentType;
    }

    public void setResponseContentType(String responseContentType) {
        if (StringUtils.isNotBlank(responseContentType)) {
            this.responseContentType = StringUtils.substringBefore(responseContentType, ";").trim().toLowerCase();
        } else {
            this.responseContentType = StringUtils.EMPTY;
        }
    }

    public boolean isEmpty() {
        return StringUtils.isAnyBlank(responseBody, responseContentType);
    }

    public String getDecodedResponseBody() {
        return decodedResponseBody;
    }

    public void setDecodedResponseBody(String decodedResponseBody) {
        this.decodedResponseBody = decodedResponseBody;
    }
}
