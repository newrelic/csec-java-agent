package com.k2cybersecurity.intcodeagent.models.javaagent;

import com.k2cybersecurity.intcodeagent.websocket.JsonConverter;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;

public class HttpResponseBean {

    private JSONObject headers;

    private String responseBody;

    private String responseCharacterEncoding;

    private String responseCharacterType;

    public HttpResponseBean() {
        this.headers = new JSONObject();
        this.responseBody = StringUtils.EMPTY;
        this.responseCharacterEncoding = StringUtils.EMPTY;
        this.responseCharacterType = StringUtils.EMPTY;
    }

    public HttpResponseBean(HttpResponseBean httpResponseBean) {
        this.headers = new JSONObject(httpResponseBean.getHeaders());
        this.responseBody = httpResponseBean.responseBody;
        this.responseCharacterEncoding = httpResponseBean.responseCharacterEncoding;
        this.responseCharacterType = httpResponseBean.responseCharacterType;
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

    public String getResponseCharacterType() {
        return responseCharacterType;
    }

    public void setResponseCharacterType(String responseCharacterType) {
        this.responseCharacterType = responseCharacterType;
    }

    public boolean isEmpty(){
        return StringUtils.isBlank(responseBody);
    }
}
